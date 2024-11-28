use capstone::prelude::*;

pub fn disass_insn(cs: &Capstone, pc: i64, raw: i32) -> String {
    let bytes = if raw % 4 == 3 {
        vec![
            raw as u8,
            (raw >> 8) as u8,
            (raw >> 16) as u8,
            (raw >> 24) as u8,
        ]
    } else {
        vec![raw as u8, (raw >> 8) as u8]
    };

    let i = &cs
        .disasm_all(&bytes, pc as u64)
        .expect("Failed to disassemble");
    if i.len() == 1 {
        let i = &i[0];
        format!(
            "{:x} {} {}",
            i.address(),
            i.mnemonic().unwrap(),
            i.op_str().unwrap_or("")
        )
    } else {
        // This might happen on garbage
        format!("{pc:x} {raw:08x}")
    }
}

pub static capstone_instance: _ = std::sync::LazyLock::new(|| build_capstone());

// XXX I hate this
#[must_use]
pub fn build_capstone() -> Capstone {
    Capstone::new()
        .riscv()
        .mode(arch::riscv::ArchMode::RiscV64)
        .extra_mode(
            [capstone::arch::riscv::ArchExtraMode::RiscVC]
                .iter()
                .copied(),
        )
        .build()
        .expect("Failed to create Capstone object")
}
