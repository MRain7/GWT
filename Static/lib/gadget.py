import math, struct, collections, logging, sys
import archinfo
import z3
import cPickle as pickle
import utils, extra_archinfo

class GadgetBase(object):
  def clobbers_register(self, reg):
    raise RuntimeError("Not Implemented")

  def clobbers_registers(self, regs):
    raise RuntimeError("Not Implemented")

  def complexity(self):
    raise RuntimeError("Not Implemented")

  def chain(self, next_address, input_values = None):
    raise RuntimeError("Not Implemented")

class Gadget(GadgetBase):
  """This class wraps a set of instructions and holds the associated metadata that makes up a gadget"""

  def __init__(self, arch, address, inputs, outputs, params, clobber, stack_offset, ip_in_stack_offset):
    self.arch = arch
    self.address = address
    self.inputs = inputs
    self.outputs = outputs
    self.params = params
    self.clobber = clobber
    self.stack_offset = stack_offset
    self.ip_in_stack_offset = ip_in_stack_offset

  def __str__(self):
    outputs = ", ".join([self.arch.translate_register_name(x) for x in self.outputs])
    if outputs != "":
      outputs = ", Output: {}".format(outputs)
    inputs = ", ".join([self.arch.translate_register_name(x) for x in self.inputs])
    if inputs != "":
      inputs = ", Inputs [{}]".format(inputs)
    clobber = ", ".join([self.arch.translate_register_name(x) for x in self.clobber])
    if clobber != "":
      clobber = ", Clobbers [{}]".format(clobber)
    params = ", ".join([hex(x) for x in self.params])
    if params != "":
      params = ", Params [{}]".format(params)
    ip = self.ip_in_stack_offset
    if self.ip_in_stack_offset != None:
      ip = "0x{:x}".format(self.ip_in_stack_offset)
    return "{}(Address: 0x{:x}, Complexity {}, Stack 0x{:x}, Ip {}{}{}{}{})".format(self.__class__.__name__,
      self.address, round(self.complexity(), 2), self.stack_offset, ip, outputs, inputs, clobber, params)

  def _is_stack_reg(self, reg):
    return reg == self.arch.registers['sp'][0]

  def clobbers_register(self, reg):
    """Check if the gadget clobbers the specified register"""
    for clobber in self.clobber:
      if clobber == reg:
        return True
    return (reg in self.outputs) or (reg in self.clobber)

  def clobbers_registers(self, regs):
    """Check if the gadget clobbers any of the specified registers"""
    for reg in regs:
      if self.clobbers_register(reg):
        return True
    return False

  def sets_registers(self, regs):
    """Returns two lists, one that lists the passed in registers that are set, and one that lists the ones that are not"""
    registers_found = []
    for reg in regs:
      if reg in self.outputs:
        registers_found.append(reg)
    return registers_found, filter(lambda x: x not in registers_found, regs)

  def complexity(self):
    """Return a rough complexity measure for a gadget that can be used to select the best gadget in a set.  Our simple formula
      is based on the number of clobbered registers, and if a normal return (i.e. with no immediate is used).  The stack decider
      helps to priorize gadgets that use less stack space (and thus can fit in smaller buffers)."""
    complexity = 0
    if self.ip_in_stack_offset == None:
      complexity += 2
    elif self.stack_offset - (self.arch.bits/8) != self.ip_in_stack_offset:
      complexity += 1

    if self.stack_offset < 0:
      complexity += 10
    elif self.stack_offset > 0:
      complexity += (math.log(self.stack_offset)/math.log(8))

    return len(self.clobber) + complexity

  def chain(self, next_address, input_values = None):
    """Default ROP Chain generation, uses no parameters"""
    chain = self.ip_in_stack_offset * "I"
    chain += utils.ap(next_address, self.arch)
    chain += (self.stack_offset - len(chain)) * "J"
    return chain

  def get_constraint(self):
    constraint, antialias_constraint = self.get_gadget_constraint()
    ip_stack_constraint = self.get_stack_ip_constraints()
    constraint = z3.Or(constraint, ip_stack_constraint)
    if antialias_constraint != None:
      constraint = z3.And(constraint, antialias_constraint)
    return constraint

  def get_gadget_constraint(self):
    raise RuntimeError("Not Implemented")

  def get_stack_ip_constraints(self):
    sp_before = self.get_reg_before(self.arch.registers['sp'][0])
    sp_after = self.get_reg_after(self.arch.registers['sp'][0])
    constraint = z3.Not(sp_after == sp_before + self.stack_offset)

    if self.ip_in_stack_offset != None:
      new_ip_value = utils.z3_get_memory(self.get_mem_before(), sp_before + self.ip_in_stack_offset, self.arch.bits, self.arch)
      ip_after = self.get_reg_after(self.arch.registers['ip'][0])
      if self.arch.name in extra_archinfo.ALIGNED_ARCHS: # For some architectures, pyvex adds a constraint to ensure new IPs are aligned
        new_ip_value = new_ip_value & ((2 ** self.arch.bits) - self.arch.instruction_alignment) # in order to properly validate, we must match that
      constraint = z3.Or(constraint, z3.Not(ip_after == new_ip_value))
    return constraint

  # Some z3 helper methods
  def get_reg_before(self, reg): return z3.BitVec("{}_before".format(self.arch.translate_register_name(reg)), self.arch.bits)
  def get_reg_after(self, reg):  return z3.BitVec("{}_after".format(self.arch.translate_register_name(reg)), self.arch.bits)
  def get_output(self, idx):     return self.get_reg_after(self.outputs[idx])
  def get_output0(self):         return self.get_output(0)
  def get_input(self, idx):      return self.get_reg_before(self.inputs[idx])
  def get_input0(self):          return self.get_input(0)
  def get_input1(self):          return self.get_input(1)
  def get_param(self, idx):      return z3.BitVecVal(self.params[idx], self.arch.bits)
  def get_param0(self):          return self.get_param(0)
  def get_mem(self, name):       return z3.Array("mem_{}".format(name), z3.BitVecSort(self.arch.bits), z3.BitVecSort(8))
  def get_mem_before(self):      return self.get_mem("before")
  def get_mem_after(self):       return self.get_mem("after")

  def get_antialias_constraint(self, address, register = "sp"):
    register = self.get_reg_before(self.arch.registers[register][0])
    num_bytes = self.arch.bits/8
    return z3.And(
      # Don't allow the address to be overlaping the register
      z3.Or(
        z3.ULT(address, register - num_bytes),
        z3.UGT(address, register + num_bytes)
      ),

      # Don't allow the address or register to wrap around
      z3.ULT(address, address + num_bytes),
      z3.UGT(address, address - num_bytes),
      z3.ULT(register, register + num_bytes),
      z3.UGT(register, register - num_bytes),
    )

###########################################################################################################
## The various Gadget types ###############################################################################
###########################################################################################################

class Jump(Gadget):
  def chain(self, next_address = None, input_values = None):
    return self.stack_offset * "K" # No parameters or IP in stack, just fill the stack offset

  def get_gadget_constraint(self):
    return z3.Not(self.get_output0() == self.get_input0()), None

class MoveReg(Gadget):
  def get_gadget_constraint(self):
    return z3.Not(self.get_output0() == self.get_input0()), None

class LoadConst(Gadget):
  def get_gadget_constraint(self):
    return z3.Not(self.get_output0() == self.get_param0()), None

class LoadMem(Gadget):
  def chain(self, next_address, input_values = None):
    chain = ""
    input_from_stack = self._is_stack_reg(self.inputs[0]) and input_values[0] != None

    # If our input value is coming from the stack, and it's supposed to come before the next PC address, add it to the chain now
    if input_from_stack and (self.ip_in_stack_offset == None or self.params[0] < self.ip_in_stack_offset):
      chain += self.params[0] * "L"
      chain += utils.ap(input_values[0], self.arch)

    if self.ip_in_stack_offset != None:
      chain += (self.ip_in_stack_offset - len(chain)) * "M"
      chain += utils.ap(next_address, self.arch)

    # If our input value is coming from the stack, and it's supposed to come after the next PC address, add it to the chain now
    if input_from_stack and self.ip_in_stack_offset != None and self.params[0] > self.ip_in_stack_offset:
      chain += (self.params[0] - len(chain)) * "N"
      chain += utils.ap(input_values[0], self.arch)

    chain += (self.stack_offset - len(chain)) * "O"
    return chain

  def get_gadget_constraint(self):
    mem_value = utils.z3_get_memory(self.get_mem_before(), self.get_input0() + self.get_param0(), self.arch.bits, self.arch)
    return z3.Not(self.get_output0() == mem_value), None

class LoadMemJump(LoadMem):
  """This gadget loads memory then jumps to a register (Used often in ARM)"""
  def get_gadget_constraint(self):
    load_constraint, antialias_constraint = super(LoadMemJump, self).get_gadget_constraint()
    jump_constraint = z3.Not(self.get_reg_after(self.arch.registers['ip'][0]) == self.get_input1())
    return z3.Or(load_constraint, jump_constraint), antialias_constraint

class LoadMultiple(LoadMem):
  """This gadget loads multiple registers at once"""
  def get_gadget_constraint(self):
    load_mem_constraint = None
    for i in range(len(self.outputs)):
      mem_value = utils.z3_get_memory(self.get_mem_before(), self.get_input0() + self.get_param(i), self.arch.bits, self.arch)
      new_constraint = z3.Not(self.get_output(i) == mem_value)
      if load_mem_constraint == None:
        load_mem_constraint = new_constraint
      else:
        load_mem_constraint = z3.Or(load_mem_constraint, new_constraint)
    return load_mem_constraint, None

  def chain(self, next_address, input_values):
    ip_added = False

    # if the registers and ip are on the stack, we have to intermingle them
    if self._is_stack_reg(self.inputs[0]):
      # Get the order to set the registers
      regs_to_params = []
      for i in range(len(self.outputs)):
        regs_to_params.append((self.params[i], self.outputs[i], i))
      regs_to_params.sort()

      chain = ""
      for param, reg, output_idx in regs_to_params:
        before_ip_on_stack = self.ip_in_stack_offset == None or param < self.ip_in_stack_offset

        # If our input value is coming from the stack, and it's supposed to come before the next PC address, add it to the chain now
        if before_ip_on_stack:
          chain += (param - len(chain)) * "P"
          chain += utils.ap(input_values[output_idx], self.arch)

        if self.ip_in_stack_offset != None and not ip_added and not before_ip_on_stack:
          chain += (self.ip_in_stack_offset - len(chain)) * "Q"
          chain += utils.ap(next_address, self.arch)
          ip_added = True

        # If our input value is coming from the stack, and it's supposed to come after the next PC address, add it to the chain now
        if not before_ip_on_stack:
          chain += (param - len(chain)) * "R"
          chain += utils.ap(input_values[output_idx], self.arch)

    # if the IP hasn't already been set, add it now
    if self.ip_in_stack_offset != None and not ip_added:
      chain += (self.ip_in_stack_offset - len(chain)) * "S"
      chain += utils.ap(next_address, self.arch)
    chain += (self.stack_offset - len(chain)) * "T"
    return chain

class StoreMem(Gadget):
  def get_gadget_constraint(self):
    address = self.get_input0() + self.get_param0()
    mem_value = utils.z3_get_memory(self.get_mem_after(), address, self.arch.bits, self.arch)

    store_constraint = z3.Not(mem_value == self.get_input1())
    antialias_constraint = self.get_antialias_constraint(address)
    return store_constraint, antialias_constraint

class Arithmetic(Gadget):
  def get_gadget_constraint(self):
    return z3.Not(self.get_output0() == self.binop(self.get_input0(), self.get_input1())), None

class ArithmeticLoad(Gadget):
  def get_gadget_constraint(self):
    mem_value = utils.z3_get_memory(self.get_mem_before(), self.get_input0() + self.get_param0(), self.arch.bits, self.arch)
    return z3.Not(self.get_output0() == self.binop(mem_value, self.get_input1())), None

class ArithmeticStore(Gadget):
  def get_gadget_constraint(self):
    address = self.get_input0() + self.get_param0()
    in_mem_value = utils.z3_get_memory(self.get_mem_before(), address, self.arch.bits, self.arch)
    out_mem_value = utils.z3_get_memory(self.get_mem_after(), address, self.arch.bits, self.arch)

    store_constraint = z3.Not(out_mem_value == self.binop(in_mem_value, self.get_input1()))
    antialias_constraint = self.get_antialias_constraint(address)
    return store_constraint, antialias_constraint

# Split up the Arithmetic gadgets, so they're easy to search for when you are searching for a specific one
class AddGadget(Arithmetic):
  @classmethod
  def binop(self,x,y): return x + y

class SubGadget(Arithmetic):
  @classmethod
  def binop(self,x,y): return x - y

class MulGadget(Arithmetic):
  @classmethod
  def binop(self,x,y): return x * y

class AndGadget(Arithmetic):
  @classmethod
  def binop(self,x,y): return x & y

class OrGadget(Arithmetic):
  @classmethod
  def binop(self,x,y): return x | y

class XorGadget(Arithmetic):
  @classmethod
  def binop(self,x,y): return x ^ y


# Split up the Arithmetic Load gadgets, so they're easy to search for when you are searching for a specific one
class LoadAddGadget(ArithmeticLoad):
  @classmethod
  def binop(self,x,y): return x + y

class LoadSubGadget(ArithmeticLoad):
  @classmethod
  def binop(self,x,y): return x - y

class LoadMulGadget(ArithmeticLoad):
  @classmethod
  def binop(self,x,y): return x * y

class LoadAndGadget(ArithmeticLoad):
  @classmethod
  def binop(self,x,y): return x & y

class LoadOrGadget(ArithmeticLoad):
  @classmethod
  def binop(self,x,y): return x | y

class LoadXorGadget(ArithmeticLoad):
  @classmethod
  def binop(self,x,y): return x ^ y

# Split up the Arithmetic Store gadgets, so they're easy to search for when you are searching for a specific one
class StoreAddGadget(ArithmeticStore):
  @classmethod
  def binop(self,x,y): return x + y

class StoreSubGadget(ArithmeticStore):
  @classmethod
  def binop(self,x,y): return x - y

class StoreMulGadget(ArithmeticStore):
  @classmethod
  def binop(self,x,y): return x * y

class StoreAndGadget(ArithmeticStore):
  @classmethod
  def binop(self,x,y): return x & y

class StoreOrGadget(ArithmeticStore):
  @classmethod
  def binop(self,x,y): return x | y

class StoreXorGadget(ArithmeticStore):
  @classmethod
  def binop(self,x,y): return x ^ y
