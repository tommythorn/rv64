use super::*;

pub struct StoreEffect {
    pub addr: i32,
    pub mask: i32,
    pub value: i32,
}

pub struct ExecEffect {
    pub nextpc: i64,
    pub res: i32,
    pub store: Option<StoreEffect>,
}

impl Insn {
    pub fn exec(&self, v1: i32, v2: i32, mem_20000000: &[i32]) -> ExecEffect {
        let mut res = 0;
        let mut nextpc = self.addr + self.size as i64;
        let mut store = None;
        let pc = self.addr;

        match self.class {
            Class::Store { size } => {
                let addr = v1.wrapping_add(self.imm as i32);
                match size {
                    1 => {
                        let mask = 255 << (8 * (addr & 3));
                        let value = (v2 & 255) << (8 * (addr & 3));
                        store = Some(StoreEffect { addr, mask, value });
                    }
                    4 => {
                        store = Some(StoreEffect {
                            addr,
                            mask: !0,
                            value: v2,
                        });
                    }
                    _ => todo!("Store size {size}"),
                }
            }

            Class::Load { size, signed } => {
                // XXX Load should also be an exported effect
                let addr = v1.wrapping_add(self.imm as i32) as usize;
                let w = mem_20000000[(addr - 0x20000000) / 4];
                match size {
                    1 if !signed => {
                        res = w >> (8 * (addr & 3)) & 255;
                    }
                    _ => todo!(
                        "Didn't handle LOAD size {size} signed {signed} from {pc:08x} {:08x}",
                        self.bits
                    ),
                }
            }

            Class::Alu => match funct3_bf(self.bits) {
                0 => {
                    let imm = self.imm;
                    // XXX I don't like this.  Maybe AluImm should be a thing?
                    let sum = v1.wrapping_add(imm as i32);
                    res = sum.wrapping_add(v2);
                }
                _ => panic!(
                    "Didn't handle OP_IMM funct3 {} from {pc:08x} {:08x}",
                    funct3_bf(self.bits),
                    self.bits
                ),
            },

            Class::Branch { cond, target } => {
                use BranchCondition::*;
                let taken = match cond {
                    Beq => v1 == v2,
                    Bne => v1 != v2,
                    Blt => v1 < v2,
                    Bge => v1 >= v2,
                    Bltu => (v1 as u32) < v2 as u32,
                    Bgeu => (v1 as u32) >= v2 as u32,
                    _ => panic!("rv64 decode should have caught this"),
                };
                if taken {
                    nextpc = target;
                }
            }
            _ => panic!(
                "Didn't handle opcode {:?} from {pc:08x} {:08x}",
                self.class, self.bits,
            ),
        }

        ExecEffect { nextpc, res, store }
    }
}
