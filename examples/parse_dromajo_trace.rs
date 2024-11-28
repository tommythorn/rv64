use std::io;
use std::io::prelude::*;

fn main() -> anyhow::Result<()> {
    let stdin = io::stdin();
    for (lineno, line) in stdin.lock().lines().enumerate() {
        //println!("{lineno}");
        match rv64::dromajo_trace::parse(&line?) {
            Ok(insn) => println!("{insn:x?}"),
            Err(err) => {
                println!("Failed on line {} of stdin", lineno + 1);
                return Err(err);
            }
        }
    }

    Ok(())
}
