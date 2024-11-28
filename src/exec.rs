use super::*;

pub struct StoreEffect {
    pub addr: i64,
    pub mask: i64,
    pub value: i64,
}

pub struct ExecEffect {
    pub nextpc: i64,
    pub res: i64,
    pub store: Option<StoreEffect>,
}

impl Insn {
    pub fn exec(&self, v1: i64, v2: i64, mem_20000000: &[i64]) -> ExecEffect {
        let mut res = 0;
        let mut nextpc = self.addr + if self.compressed { 2 } else { 4 };
        let mut store = None;
        let pc = self.addr;

        match self.class {
            Class::Store { size, imm } => {
                let addr = v1.wrapping_add(imm as i64);
                match size {
                    1 => {
                        let mask = 255 << (8 * (addr & 7));
                        let value = (v2 & 255) << (8 * (addr & 7));
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

            Class::Load { size, imm, signed } => {
                // XXX Load should also be an exported effect
                let addr = v1.wrapping_add(imm as i64);
                let w = mem_20000000[(addr as usize - 0x20000000) / 4];
                match size {
                    1 if !signed => {
                        res = w >> (8 * (addr & 7)) & 255;
                    }
                    _ => todo!(
                        "Didn't handle LOAD size {size} signed {signed} from {pc:08x} {:08x}",
                        self.bits
                    ),
                }
            }

            Class::Alu(AluOp::Add, w) => {
                res = v1.wrapping_add(v2);
                if w {
                    res = (res as i32) as i64;
                }
            }

            Class::AluImm(AluOp::Add, w, imm) => {
                res = v1.wrapping_add(imm as i64);
                if w {
                    res = (res as i32) as i64;
                }
            }

            Class::Imm(imm) => res = imm,

            Class::Branch { cond, target } => {
                use BranchCondition::*;
                let taken = match cond {
                    Eq => v1 == v2,
                    Ne => v1 != v2,
                    Lt => v1 < v2,
                    Ge => v1 >= v2,
                    Ltu => (v1 as u32) < v2 as u32,
                    Geu => (v1 as u32) >= v2 as u32,
                    _ => panic!("rv64 decode should have caught this"),
                };
                if taken {
                    nextpc = target;
                }
            }

            Class::JumpR(imm) => {
                res = nextpc;
                nextpc = (v1 + imm as i64) & !-2;
            }

            _ => panic!(
                "Didn't handle opcode {:?} from {pc:08x} {:08x}",
                self.class, self.bits,
            ),
        }

        ExecEffect { nextpc, res, store }
    }
}
