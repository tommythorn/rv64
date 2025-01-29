/* Quick and dirty utility to parse Dromajo traces */
use super::*;

// Example:
// 0 3 0x000000800000000c (0x654000ef) x 1 0x0000008000000010
// 0 3 0x0000008000000662 (0x00008082)
// 0 3 0x0000008000000660 (0x0000557d) x10 0xffffffffffffffff

#[test]
fn check_parse() {
    let trace = "0 3 0x000000800000000c (0x654000ef) x 1 0x0000008000000010
0 3 0x0000008000000662 (0x00008082)
0 3 0x0000008000000660 (0x0000557d) x10 0xffffffffffffffff
0 1 0xffffffe00000105c (0x00008082)
0 1 0xffffffe000002072 (0x846ff0ef) x 1 0xffffffe000002076
0 1 0xffffffe0000010b8 (0x00200517) x10 0xffffffe0002010b8
";

    let expected = [
        Insn {
            seqno: 0,
            addr: 0x800000000c,
            bits: 0x654000ef,
            class: Class::Jump {
                target: 0x8000000660,
            },
            rd: 1,
            rs1: 0,
            rs2: 0,
        },
        Insn {
            seqno: 0,
            addr: 0x8000000662,
            bits: 0x8082,
            class: Class::JumpR(0),
            rd: 0,
            rs1: 1,
            rs2: 0,
        },
        Insn {
            seqno: 0,
            addr: 0x8000000660,
            bits: 0x557d,
            class: Class::Imm(!0),
            rd: 10,
            rs1: 0,
            rs2: 0,
        },
        Insn {
            seqno: 0,
            addr: 0xffffffe00000105cu64 as i64,
            bits: 0x00008082,
            class: Class::JumpR(0),
            rd: 0,
            rs1: 1,
            rs2: 0,
        },
    ];

    for (line, expect) in trace.lines().zip(expected) {
        let insn = parse(line).expect("This should have been parsable");
        assert_eq!(insn, expect, "got {insn:x?}");
    }
}

pub fn parse(line: &str) -> anyhow::Result<Insn> {
    // XXX Terribly poor error handling
    let parts: Vec<&str> = line.split_whitespace().collect();
    let _prv = u8::from_str_radix(parts[1], 16).expect(parts[1]);
    let addr = u64::from_str_radix(&parts[2][2..], 16).expect(parts[2]) as i64;
    let bits = &parts[3];
    let bits = u32::from_str_radix(&bits[3..11], 16).expect(bits) as i32;
    let insn = decode(0, addr, bits, 64);
    Ok(insn)
}
