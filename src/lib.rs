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

#[derive(Copy, Clone, FromPrimitive)]
pub enum OpcodeBranch {
    Beq,
    Bne,
    Uimpbr2,
    Uimpbr3,
    Blt,
    Bge,
    Bltu,
    Bgeu,
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

#[derive(Debug)]
pub enum Class {
    Illegal,
    Alu,
    Load,
    Store,
    Jump,
    Branch,
    Compjump,
    Atomic,
}

#[allow(dead_code)]
pub struct Insn {
    insn_addr: i64,
    insn: i32,
    insn_len: usize, // typically 4 or 2
    class: Class,
    rd: Reg,
    rs1: Reg,
    rs2: Reg,
    csrd: Option<Csr>,
    csrs: Option<Csr>,
    system: bool, // system instruction are handled differently
    imm: i64,     // generalized optional immediate
    memop_size: usize,
    sext_load: bool,
    target: i64, // For jumps and branches
}

impl fmt::Display for Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:x} {:08x} {:6} {:14}  #{}  {:x}",
            self.insn_addr,
            self.insn,
            format!("{:?}", self.class).to_lowercase(),
            format!(
                "{:3} = x{}, x{}",
                format_args!("x{}", self.rd),
                self.rs1,
                self.rs2
            ),
            self.imm,
            self.target
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
pub fn itype_imm12_bf(insn: i32) -> i64 {
    (insn >> 20) as i64
}
// S-type
pub fn stype_imm12_bf(insn: i32) -> i64 {
    ((insn >> 25 << 5) | ((insn >> 7) & 31)) as i64
}
// SB-type
pub fn sbtype_imm12_bf(insn: i32) -> i64 {
    let imm4_1 = (insn >> 8) & 15;
    let imm10_5 = (insn >> 25) & 63;
    let imm11 = (insn >> 7) & 1;
    let imm12 = insn >> 31;
    ((imm12 << 12) | (imm11 << 11) | (imm10_5 << 5) | (imm4_1 << 1)) as i64
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
    assert_eq!(sbtype_imm12_bf(0x00071863), (0x80000550i64 - 0x80000540i64));
    // 800037b4:       fc070ee3                beq     x14,x0,80003790 <__sflush_r+0x54>
    assert_eq!(
        sbtype_imm12_bf(0xfc070ee3u32 as i32),
        (0x80003790i64 - 0x800037b4i64)
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

pub fn decode(insn_addr: i64, orig_insn: i32, _xlen: usize) -> Insn {
    let insn: i32 = /*rvcdecoder(orig_insn, xlen)*/ orig_insn;

    let base: Insn = Insn {
        insn_addr,
        insn,
        insn_len: if opext_bf(orig_insn) == 3 { 4 } else { 2 },
        class: Class::Illegal,
        rd: 0,
        rs1: 0,
        rs2: 0,
        csrd: None,
        csrs: None,
        system: false,
        imm: 0,
        memop_size: 0,
        sext_load: false,
        target: 0,
    };

    let rd = rd_bf(insn);
    let rs1 = rs1_bf(insn);
    let rs2 = rs2_bf(insn);
    let funct3 = funct3_bf(insn);
    let funct7 = funct7_bf(insn);

    use Opcode::*;
    match FromPrimitive::from_i32(opcode_bf(insn)).unwrap() {
        Load => Insn {
            class: Class::Load,
            rd,
            rs1,
            imm: itype_imm12_bf(insn),
            memop_size: 1 << (funct3 & 3),
            sext_load: funct3 < LoadKind::Lw as i32,
            ..base
        },

        LoadFp => Insn {
            // XXX Pretend it's a nop
            class: Class::Alu,
            ..base
        },

        MiscMem => Insn {
            class: Class::Branch,
            system: true,
            ..base
        },

        OpImm | OpImm32 => Insn {
            class: Class::Alu,
            rd,
            rs1,
            imm: itype_imm12_bf(insn),
            ..base
        },

        Auipc => Insn {
            class: Class::Alu,
            rd,
            imm: insn_addr + utype_imm20_bf(insn),
            ..base
        },

        Lui => Insn {
            class: Class::Alu,
            rd,
            imm: utype_imm20_bf(insn),
            ..base
        },

        Store if funct3 <= 3 => Insn {
            class: Class::Store,
            rs1,
            rs2,
            imm: stype_imm12_bf(insn),
            memop_size: 1 << (funct3 & 3),
            ..base
        },

        StoreFp => Insn {
            class: Class::Alu, // nop
            ..base
        },

        Amo => {
            let base = Insn {
                rd,
                rs1,
                memop_size: if (funct3 & 1) != 0 { 8 } else { 4 },
                sext_load: (funct3 & 1) == 0,
                ..base
            };

            match FromPrimitive::from_i32(funct7 >> 2) {
                Some(OpcodeAmo::Lr) => Insn {
                    class: Class::Load,
                    ..base
                },

                Some(OpcodeAmo::Sc) => Insn {
                    class: Class::Store,
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

                _ => Insn {
                    class: Class::Illegal,
                    ..base
                },
            }
        }

        Op | Op32 => {
            /* RV32M */
            /* XXX
            if funct7 != 1 && (!((funct3 == AddSub || funct3 == Sral) && funct7 == 0x20 || i.r.funct7 == 0x00)) {
                panic!("goto unhandled;");
            }
             */

            Insn {
                class: Class::Alu,
                rd,
                rs1,
                rs2,
                ..base
            }
        }

        Branch => Insn {
            class: Class::Branch,
            rs1,
            rs2,
            target: insn_addr + sbtype_imm12_bf(insn),
            ..base
        },

        Jalr => Insn {
            class: Class::Compjump,
            rd,
            rs1,
            imm: itype_imm12_bf(insn),
            ..base
        },

        Jal => Insn {
            class: Class::Jump,
            rd,
            target: insn_addr + ujtype_imm20_bf(insn),
            ..base
        },

        /*
        System => Insn {
                  dec.system = true;
                  switch (i.r.funct3) {
                  case ECALLEBREAK:
                      switch (i.i.imm11_0) {
                      case ECALL:
                      case EBREAK:
                      case SRET:
                      case MRET:
                          class: isa_insn_class_compjump;
                          break;

                      case WFI:
                          class: Class::Alu,
                          break;
                      }
                      break;

                  case CSRRS:
                      if (i.i.rs1:= 0) {
                          dec.source_msr_a = 0xFFF & (unsigned) i.i.imm11_0;
                          rd,
                          class: Class::Alu,
                          // XXX treating this as non-sequential is fragile, but
                          // works except for xSTATUS, INSTRET, and CYCLE
                          break;
                      }
                      /* Fall-through */

                  case CSRRC:
                      rs1,
                  case CSRRSI:
                  case CSRRCI:
                      dec.source_msr_a = 0xFFF & (unsigned) i.i.imm11_0;
                      dec.dest_msr     = 0xFFF & (unsigned) i.i.imm11_0;
                      rd,
                      class: Class::Alu,
                      break;

                  case CSRRW:
                      rs1,
                  case CSRRWI:
                      dec.dest_msr     = 0xFFF & (unsigned) i.i.imm11_0;
                      rd,
                      class: Class::Alu,

                      if (i.i.rd)
                          dec.source_msr_a = 0xFFF & (unsigned) i.i.imm11_0;
                      break;

                  default:
                      goto unhandled;
                  }
                  break;

                Op_FP => Insn {
                    switch (i.r.funct7) {
                    case FMV_D_X:
                        class: Class::Alu, // XXX alu_fp?
                        //dec.source_freg_a = i.r.rs1;
                        //dec.dest_freg     = i.r.rd;
                        break;
                    default: goto unhandled;
                    }
                    break;

                default:
                unhandled:
                    /*
                    warn("Opcode %s not decoded, insn %08"PRIx32":%08x\n",
                         opcode_name[i.r.opcode], (uint32_t)insn_addr, i.raw);
                    */
                    break;
                }
        */
        _ => panic!("not done yet"),
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

    let insns: [u32; 16] = [
        0x04100693, 0x20d98c23, 0x04200693, 0x20d40ca3, 0x00012683, 0x01ec4703, 0x00100793,
        0x04d12823, 0x00412683, 0x22478513, 0xf0dee0ef, 0x21cca503, 0xc85ee0ef, 0x21944683,
        0x04000713, 0x64d77063,
    ];

    println!();
    for (i, insn) in insns.iter().enumerate() {
        println!("{}", decode(0x800113fci64 + 4 * i as i64, *insn as i32, 32));
    }
}
