//mod disass;
pub mod dromajo_trace;
mod exec;
mod rvc;
//pub use disass::*;
pub use exec::*;
use rvc::RVC64_EXPANDED;

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::fmt;

// We represent RISC-V instructions more abstractly to be easier to
// work on
pub type Reg = u8;
pub type Csr = u16;

#[derive(Copy, Clone, FromPrimitive, Debug)]
pub enum Opcode {
    Load,
    LoadFp,
    Custom0,
    MiscMem,
    OpImm,
    Auipc,
    OpImm32,
    Ext0,
    Store,
    StoreFp,
    Custom1,
    Amo,
    Op,
    Lui,
    Op32,
    Ext1,
    Madd,
    Msub,
    Nmsub,
    Nmadd,
    OpFp,
    Res1,
    Custom2,
    Ext2,
    Branch,
    Jalr,
    Res0,
    Jal,
    System,
    Res2,
    Custom3,
    Ext3,
}

#[derive(Copy, Clone, FromPrimitive)]
pub enum OpcodeOp {
    AddSub,
    Sll,
    Slt,
    Sltu,
    Xor,
    Sral,
    Or,
    And,
}

#[derive(Copy, Clone, FromPrimitive)]
pub enum OpcodeOpImm {
    Addi,
    Slli,
    Slti,
    Sltiu,
    Xori,
    Srali,
    Ori,
    Andi,
}

#[derive(Copy, Clone, FromPrimitive, Debug, PartialEq)]
pub enum BranchCondition {
    Eq,
    Ne,
    Uimpbr2,
    Uimpbr3,
    Lt,
    Ge,
    Ltu,
    Geu,
}

impl fmt::Display for BranchCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&format!("{self:?}").to_lowercase())
    }
}

#[derive(Copy, Clone, FromPrimitive, Debug, PartialEq)]
pub enum OpcodeOpSystem {
    EcallEbreak,
    CsrRW,
    CsrRS,
    CsrRC,
    Reserved,
    CsrRWI,
    CsrRSI,
    CsrRCI,
}

#[derive(Copy, Clone, FromPrimitive)]
pub enum LoadKind {
    Lb,
    Lh,
    Lw,
    Ld,
    Lbu,
    Lhu,
    Lwu,
}

#[derive(Copy, Clone, FromPrimitive)]
pub enum OpcodeMulDiv {
    Mul,
    Mulh,
    Mulhsu,
    Mulhu,
    Div,
    Divu,
    Rem,
    Remu,
}

#[derive(Copy, Clone, FromPrimitive)]
pub enum OpcodeAmo {
    Amoadd = 0,
    Amoswap = 1,
    Lr = 2,
    Sc = 3,
    Amoxor = 4,

    Amoor = 8,
    Amoand = 12,
    Amomin = 16,
    Amomax = 20,
    Amominu = 24,
    Amomaxu = 28,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AluOp {
    Add,
    Sub,
    Sll,
    Slt,
    Sltu,
    Xor,
    Srl,
    Sra,
    Or,
    And,
    Mul,
    Mulh,
    Mulhsu,
    Mulhu,
    Div,
    Divu,
    Rem,
    Remu,
}

impl fmt::Display for AluOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format!("{self:?}").to_lowercase())
    }
}

#[derive(PartialEq, Debug)]
pub enum CsrOp {
    Set,
    Clear,
    Write,
}

#[derive(PartialEq, Debug)]
pub enum Fence {
    Mem,
    I,
}

/// `Class` is a slightly abstracted RISC-V RV64 instruction, aiming
/// to reduce the amount of RISC-V specific knowledge into just a few
/// classes.  NB: auipc and lui are both represented as `Imm(imm)`.
/// Branch and jump targets are also resolved and represented with the
/// full i64 target address.

// XXX For fast interpretation it might be better to expand this fully
// into all the possible cases, eg. Li, Add, AddI, Addw, ..., Lb, Lbu, ...,
// Beq, .. ?

#[derive(PartialEq, Debug)]
pub enum Class {
    Imm(i64),
    Alu(AluOp, bool),
    AluImm(AluOp, bool, i16),
    CsrOp {
        op: CsrOp,
        dst: Option<Csr>,
        src: Option<Csr>,
        imm: Option<u8>,
    },
    Load {
        size: usize,
        imm: i16,
        signed: bool,
    },
    Store {
        size: usize,
        imm: i16,
    },
    Branch {
        target: i64,
        cond: BranchCondition,
    },
    Jump {
        target: i64,
    },
    JumpR(i16),
    Atomic,
    Fence(Fence),
    Illegal,
    Todo, // Meaning I found something i don't understand but let's keep going
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format!("{self:?}").to_lowercase())
    }
}

#[derive(PartialEq, Debug)]
pub struct Insn {
    pub seqno: usize,
    pub addr: i64,
    pub bits: i32,

    // Decoded
    pub class: Class,
    pub rd: Reg,
    pub rs1: Reg,
    pub rs2: Reg,
}

impl fmt::Display for Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:x} {:08x} {:35} {:14}",
            self.addr,
            self.bits,
            self.class,
            format!(
                "{:3} = x{}, x{}",
                format_args!("x{}", self.rd),
                self.rs1,
                self.rs2
            )
        )
    }
}

pub fn opext_bf(insn: i32) -> i32 {
    insn & 3
}
pub fn opcode_bf(insn: i32) -> i32 {
    (insn >> 2) & 31
}
pub fn rd_bf(insn: i32) -> Reg {
    ((insn >> 7) & 31) as Reg
}
pub fn funct3_bf(insn: i32) -> i32 {
    (insn >> 12) & 7
}
pub fn rs1_bf(insn: i32) -> Reg {
    ((insn >> 15) & 31) as Reg
}
pub fn rs2_bf(insn: i32) -> Reg {
    ((insn >> 20) & 31) as Reg
}
pub fn funct7_bf(insn: i32) -> i32 {
    (insn >> 25) & 127
}

// I-type
pub fn itype_imm12_bf(insn: i32) -> i16 {
    (insn >> 20) as i16
}
// S-type
pub fn stype_imm12_bf(insn: i32) -> i16 {
    ((insn >> 25 << 5) | ((insn >> 7) & 31)) as i16
}
// SB-type
pub fn sbtype_imm12_bf(insn: i32) -> i16 {
    let imm4_1 = (insn >> 8) & 15;
    let imm10_5 = (insn >> 25) & 63;
    let imm11 = (insn >> 7) & 1;
    let imm12 = insn >> 31;
    ((imm12 << 12) | (imm11 << 11) | (imm10_5 << 5) | (imm4_1 << 1)) as i16
}
// U-type
pub fn utype_imm20_bf(insn: i32) -> i64 {
    (insn >> 12 << 12) as i64
}
// UJ-type
pub fn ujtype_imm20_bf(insn: i32) -> i64 {
    let imm19_12 = (insn >> 12) & 255;
    let imm11 = (insn >> 20) & 1;
    let imm10_1 = (insn >> 21) & 1023;
    let imm20 = insn >> 31;
    ((imm20 << 20) | (imm19_12 << 12) | (imm11 << 11) | (imm10_1 << 1)) as i64
}

#[test]
fn decoders() {
    // 3 80011484 2efa2623 sw      a5,748(s4)               [0x800162ec] <- 0x00000001
    assert_eq!(stype_imm12_bf(0x2efa2623), 748);
    // 800000f0:       84f18223                sb      x15,-1980(x3) # 80013aa4 <completed.5430>
    assert_eq!(stype_imm12_bf(0x84f18223u32 as i32), -1980);

    // 80000540:       00071863                bne     x14,x0,80000550 <_sbrk+0x1c>
    assert_eq!(
        sbtype_imm12_bf(0x00071863),
        (0x80000550i64 - 0x80000540i64) as i16
    );
    // 800037b4:       fc070ee3                beq     x14,x0,80003790 <__sflush_r+0x54>
    assert_eq!(
        sbtype_imm12_bf(0xfc070ee3u32 as i32),
        (0x80003790i64 - 0x800037b4i64) as i16
    );
    // 80000644:       7ed020ef                jal     x1,80003630 <__call_exitprocs>
    // 8000065c:       f01ff0ef                jal     x1,8000055c <_exit>
    // 800006a0:       9a5ff06f                jal     x0,80000044 <_fini>
    assert_eq!(
        ujtype_imm20_bf(0x7ed020efu32 as i32),
        0x80003630i64 - 0x80000644i64
    );
    assert_eq!(
        ujtype_imm20_bf(0xf01ff0efu32 as i32),
        0x8000055ci64 - 0x8000065ci64
    );
    assert_eq!(
        ujtype_imm20_bf(0x9a5ff06fu32 as i32),
        0x80000044i64 - 0x800006a0i64
    );
}

impl Insn {
    fn compressed(&self) -> bool {
        self.bits & 3 != 3
    }

    pub fn disass(&self) -> String {
        let pc = self.addr;
        let rd = self.rd;
        let rs1 = self.rs1;
        let rs2 = self.rs2;

        match self.class {
            Class::Store { size, imm } => match size {
                1 => format!("sb      {imm}(x{rs1}),x{rs2}"),
                4 => format!("sw      {imm}(x{rs1}),x{rs2}"),
                _ => todo!("Store size {size}"),
            },
            Class::Load { size, imm, signed } => match size {
                1 if !signed => format!("lbu     x{rd}={imm}(x{rs1})"),
                _ => todo!(
                    "Didn't handle LOAD size {size} signed {signed} from {pc:08x} {:08x}",
                    self.bits
                ),
            },
            Class::Alu(AluOp::Add, w) => {
                if self.rs2 == 0 && !w {
                    format!("mv      x{rd}=x{rs1}")
                } else {
                    format!("add{}    x{rd}=x{rs1},x{rs2}", if w { "w" } else { " " })
                }
            }
            Class::Alu(op, w) => format!(
                "{:8}x{rd}=x{rs1},x{rs2}",
                format!("{op:?}{}", if w { "w" } else { " " }).to_lowercase()
            ),
            Class::AluImm(op, w, imm) => format!(
                "{:8}x{rd}=x{rs1},{imm}",
                format!("{op:?}{}", if w { "w" } else { " " }).to_lowercase()
            ),
            Class::Imm(imm) => format!("li      x{rd}={imm}"),
            Class::Branch { cond, target } => format!("b{cond:3}    x{rs1},x{rs2},0x{target:x}"),
            Class::JumpR(imm) => format!("jalr    x{rd}=x{rs1},{imm}"),
            _ => todo!(
                "Didn't handle opcode {:?} from {pc:08x} {:08x}",
                self.class,
                self.bits,
            ),
        }
    }
}

pub fn decode(seqno: usize, addr: i64, orig_bits: i32, _xlen: usize) -> Insn {
    let bits: i32 = if orig_bits & 3 == 3 {
        orig_bits
    } else {
        RVC64_EXPANDED[(orig_bits & 0xFFFF) as usize] as i32
    };

    let base: Insn = Insn {
        seqno,
        addr,
        bits: orig_bits,
        class: Class::Illegal,
        rd: 0,
        rs1: 0,
        rs2: 0,
    };

    let rd = rd_bf(bits);
    let rs1 = rs1_bf(bits);
    let rs2 = rs2_bf(bits);
    let funct3 = funct3_bf(bits) as usize;
    let funct7 = funct7_bf(bits) as usize;

    use AluOp::*;
    use Opcode::*;
    match FromPrimitive::from_i32(opcode_bf(bits)).unwrap() {
        Load => Insn {
            class: Class::Load {
                size: 1 << (funct3 & 3),
                imm: itype_imm12_bf(bits),
                signed: funct3 < LoadKind::Lw as usize,
            },
            rd,
            rs1,
            ..base
        },

        LoadFp => Insn {
            // XXX Pretend it's a nop, for now
            class: Class::Alu(AluOp::Add, false),
            ..base
        },

        MiscMem => match funct3 {
            0 => Insn {
                class: Class::Fence(Fence::Mem),
                ..base
            },
            1 => Insn {
                class: Class::Fence(Fence::I),
                ..base
            },
            _ => todo!("MiscMem need finer decoding? {addr:x}:{bits:08x} (funct3 {funct3})"),
        },

        Op => {
            let op = match (funct7, funct3) {
                (0, _) => [Add, Sll, Slt, Sltu, Xor, Srl, Or, And][funct3],
                (1, _) => [Mul, Mulh, Mulhsu, Mulhu, Div, Divu, Rem, Remu][funct3],
                (32, 0) => Sub,
                (32, 5) => Sra,
                _ => {
                    return base; // Illegal
                }
            };

            Insn {
                class: Class::Alu(op, false),
                rd,
                rs1,
                rs2,
                ..base
            }
        }

        Op32 => {
            let imm = bits >> 25;
            let op = if imm == 1 {
                match funct3 {
                    0 => Mul,
                    4 => Div,
                    5 => Divu,
                    6 => Rem,
                    7 => Remu,
                    _ => {
                        return base; // Illegal
                    }
                }
            } else {
                match (imm, funct3) {
                    (0, 0) => Add,
                    (32, 0) => Sub,
                    (0, 1) => Sll,
                    (0, 5) => Srl,
                    (32, 5) => Sra,
                    _ => {
                        return base; // Illegal
                    }
                }
            };

            Insn {
                class: Class::Alu(op, true),
                rd,
                rs1,
                rs2,
                ..base
            }
        }

        OpImm => {
            // NB: This is very specifically for RV64
            let mut imm = itype_imm12_bf(bits);
            let op = match (funct7, funct3) {
                (0 | 1, 1) => Sll,
                (0 | 1, 5) => Srl,
                (32 | 33, 5) => {
                    imm &= 63;
                    Sra
                }
                (_, 0 | 2 | 3 | 4 | 6 | 7) => [Add, Sll, Slt, Sltu, Xor, Srl, Or, And][funct3],
                _ => {
                    return base; // Illegal
                }
            };

            Insn {
                class: if op == Add && rs1 == 0 {
                    Class::Imm(imm as i64)
                } else {
                    Class::AluImm(op, false, imm)
                },
                rd,
                rs1,
                ..base
            }
        }

        OpImm32 => {
            let mut imm = itype_imm12_bf(bits);
            let op = match (funct7, funct3) {
                (_, 0) => Add,
                (0, 1) => Sll,
                (0, 5) => Srl,
                (32, 5) => {
                    imm &= 31;
                    Sra
                }
                _ => {
                    return base; // Illegal
                }
            };

            Insn {
                class: Class::AluImm(op, true, imm),
                rd,
                rs1,
                ..base
            }
        }

        Auipc => Insn {
            class: Class::Imm(addr.wrapping_add(utype_imm20_bf(bits))),
            rd,
            ..base
        },

        Lui => Insn {
            class: Class::Imm(utype_imm20_bf(bits)),
            rd,
            ..base
        },

        Store if funct3 <= 3 => Insn {
            class: Class::Store {
                size: 1 << (funct3 & 3),
                imm: stype_imm12_bf(bits),
            },
            rs1,
            rs2,
            ..base
        },

        StoreFp => Insn {
            class: Class::Alu(AluOp::Add, false), // nop
            ..base
        },

        Amo => {
            let size = if funct3 & 1 != 0 { 8 } else { 4 };
            let signed = funct3 & 1 == 0;
            let base = Insn { rd, rs1, ..base };

            match FromPrimitive::from_usize(funct7 >> 2) {
                Some(OpcodeAmo::Lr) => Insn {
                    class: Class::Load {
                        size,
                        imm: stype_imm12_bf(bits),
                        signed,
                    },
                    ..base
                },

                Some(OpcodeAmo::Sc) => Insn {
                    class: Class::Store { size, imm: 0 },
                    rs2,
                    ..base
                },

                Some(OpcodeAmo::Amoadd)
                | Some(OpcodeAmo::Amoand)
                | Some(OpcodeAmo::Amomax)
                | Some(OpcodeAmo::Amomaxu)
                | Some(OpcodeAmo::Amomin)
                | Some(OpcodeAmo::Amominu)
                | Some(OpcodeAmo::Amoor)
                | Some(OpcodeAmo::Amoswap)
                | Some(OpcodeAmo::Amoxor) => Insn {
                    class: Class::Atomic,
                    rs2,
                    ..base
                },

                _ => base, // Illegal
            }
        }

        Branch => Insn {
            class: Class::Branch {
                cond: FromPrimitive::from_i32(funct3_bf(bits)).unwrap(),
                target: addr.wrapping_add(sbtype_imm12_bf(bits) as i64),
            },
            rs1,
            rs2,
            ..base
        },

        Jalr => Insn {
            class: Class::JumpR(itype_imm12_bf(bits)),
            rd,
            rs1,
            ..base
        },

        Jal => Insn {
            class: Class::Jump {
                target: addr.wrapping_add(ujtype_imm20_bf(bits)),
            },
            rd,
            ..base
        },

        System => {
            use OpcodeOpSystem::*;
            let prim = FromPrimitive::from_i32(funct3_bf(bits)).unwrap();
            match prim {
                EcallEbreak => Insn {
                    class: Class::Todo,
                    ..base
                },
                CsrRW | CsrRS | CsrRC | CsrRWI | CsrRSI | CsrRCI => {
                    let src = match prim {
                        // Special case: with no register destination,
                        // the CSR is only written, not read
                        CsrRW if rd == 0 => None,
                        CsrRWI if rd == 0 => None,
                        _ => Some(itype_imm12_bf(bits) as u16),
                    };
                    let dst = match prim {
                        CsrRS if rs1 == 0 => {
                            // Special case: with no source register,
                            // the CSR is only read, not written
                            None
                        }
                        _ => Some(itype_imm12_bf(bits) as u16),
                    };
                    let op = match prim {
                        CsrRS | CsrRSI => CsrOp::Set,
                        CsrRC | CsrRCI => CsrOp::Clear,
                        CsrRW | CsrRWI => CsrOp::Write,
                        _ => unreachable!(),
                    };
                    let imm = match prim {
                        CsrRSI | CsrRCI | CsrRWI => Some(rs1_bf(bits)),
                        _ => None,
                    };
                    Insn {
                        class: Class::CsrOp { op, dst, src, imm },
                        rd,
                        rs1,
                        ..base
                    }
                }
                _ => base, // Illegal
            }
        }

        _ => Insn {
            class: Class::Todo,
            ..base
        },
    }
}

#[test]
fn parse_riscv() {
    // 800113fc:       04100693                addi    x13,x0,65
    // 80011400:       20d98c23                sb      x13,536(x19) # 80016218 <_end+0xffffff20>
    // 80011404:       04200693                addi    x13,x0,66
    // 80011408:       20d40ca3                sb      x13,537(x8) # 80016219 <_end+0xffffff21>
    // 8001140c:       00012683                lw      x13,0(x2)
    // 80011410:       01ec4703                lbu     x14,30(x24)
    // 80011414:       00100793                addi    x15,x0,1
    // 80011418:       04d12823                sw      x13,80(x2)
    // 8001141c:       00412683                lw      x13,4(x2)
    // ...
    // 800114ac:       22478513                addi    x10,x15,548 # 80016224 <_end+0xffffff2c>
    // 800114b0:       f0dee0ef                jal     x1,800003bc <Proc_8>
    // 800114b4:       21cca503                lw      x10,540(x25)
    // 800114b8:       c85ee0ef                jal     x1,8000013c <Proc_1>
    // 800114bc:       21944683                lbu     x13,537(x8)
    // 800114c0:       04000713                addi    x14,x0,64
    // 800114c4:       64d77063                bgeu    x14,x13,80011b04 <main+0x908>
    // 1000009c:       011b8833                add     v0,a5,v1
    // 80000130:       4041d233                sra     tp,gp,tp
    // 8000223c:       41f55893                srai    a7,a0,0x1f
    // 8000013c:       0071d3b3                srl     t2,gp,t2
    // 80000124:       01f1d313                srli    t1,gp,0x1f
    // 800000ac:       01f51513                slli    a0,a0,0x1f

    let insns: [u32; 22] = [
        0x04100693, 0x20d98c23, 0x04200693, 0x20d40ca3, 0x00012683, 0x01ec4703, 0x00100793,
        0x04d12823, 0x00412683, 0x22478513, 0xf0dee0ef, 0x21cca503, 0xc85ee0ef, 0x21944683,
        0x04000713, 0x64d77063, 0x011b8833, 0x4041d233, 0x41f55893, 0x0071d3b3, 0x01f1d313,
        0x01f51513,
    ];

    println!();
    for (i, insn) in insns.iter().enumerate() {
        println!(
            "{}",
            decode(i, 0x800113fci64 + 4 * i as i64, *insn as i32, 32)
        );
    }
}
