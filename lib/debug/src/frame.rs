#![allow(non_upper_case_globals)]

use cranelift_codegen::isa::{CallConv, RegUnit, TargetIsa};
use cranelift_entity::EntityRef;
use cranelift_wasm::DefinedFuncIndex;
use std::collections::HashMap;
use std::vec::Vec;
use wasmtime_environ::{FrameLayoutCommand, FrameLayouts};

use gimli::write::{
    Address, CallFrameInstruction, CommonInformationEntry as CIEEntry, Error,
    FrameDescriptionEntry as FDEEntry, FrameTable,
};
use gimli::{Encoding, Format, Register, X86_64};

fn map_reg(isa: &TargetIsa, reg: RegUnit) -> Register {
    static mut REG_X86_MAP: Option<HashMap<RegUnit, Register>> = None;
    // FIXME lazy initialization?
    unsafe {
        if REG_X86_MAP.is_none() {
            REG_X86_MAP = Some(HashMap::new());
        }
        if let Some(val) = REG_X86_MAP.as_mut().unwrap().get(&reg) {
            return *val;
        }
        assert!(isa.name() == "x86");
        let name = format!("{}", isa.register_info().display_regunit(reg));
        let result = match name.as_str() {
            "%rax" => X86_64::RAX,
            "%rdx" => X86_64::RDX,
            "%rcx" => X86_64::RCX,
            "%rbx" => X86_64::RBX,
            "%rsi" => X86_64::RSI,
            "%rdi" => X86_64::RDI,
            "%rbp" => X86_64::RBP,
            "%rsp" => X86_64::RSP,
            "%r16" => X86_64::RA,
            _ => panic!("{}", reg),
        };
        REG_X86_MAP.as_mut().unwrap().insert(reg, result);
        result
    }
}

pub fn get_debug_frame_bytes(
    funcs: &Vec<(*const u8, usize)>,
    isa: &TargetIsa,
    layouts: &FrameLayouts,
) -> Result<FrameTable, Error> {
    assert!(isa.name() == "x86");
    // Expecting all function with System V prologue
    for l in layouts.values() {
        assert!(
            l.call_conv == CallConv::Fast
                || l.call_conv == CallConv::Cold
                || l.call_conv == CallConv::SystemV
        );
    }

    let encoding = Encoding {
        format: Format::Dwarf32,
        version: 4,
        address_size: isa.pointer_bytes(),
    };
    let mut table = FrameTable::new(encoding);

    let mut cie = CIEEntry::new(1, -8, X86_64::RA);
    cie.add_instruction(CallFrameInstruction::Cfa(X86_64::RSP, 8));
    cie.add_instruction(CallFrameInstruction::Offset(X86_64::RA, -8));
    let cie = table.add_cie(cie);

    for (i, f) in funcs.into_iter().enumerate() {
        let mut cfa_def_reg = X86_64::RSP;
        let mut cfa_def_offset = 8i32;

        let address = Address::Relative {
            symbol: i,
            addend: 0,
        };
        let f_len = f.1 as u32;
        let mut fde = FDEEntry::new(cie, address, f_len);

        let mut offset = 0;
        let layout = &layouts[DefinedFuncIndex::new(i)];
        for cmd in layout.commands.into_iter() {
            let instr = match cmd {
                FrameLayoutCommand::MoveLocationBy(delta) => {
                    offset += *delta as u32;
                    continue; // no instructions
                }
                FrameLayoutCommand::CallFrameAddressAt { reg, offset } => {
                    let mapped = map_reg(isa, *reg);
                    let offset = (*offset) as i32;
                    if mapped != cfa_def_reg && offset != cfa_def_offset {
                        cfa_def_reg = mapped;
                        cfa_def_offset = offset;
                        CallFrameInstruction::Cfa(mapped, offset)
                    } else if offset != cfa_def_offset {
                        cfa_def_offset = offset;
                        CallFrameInstruction::CfaOffset(offset)
                    } else if mapped != cfa_def_reg {
                        cfa_def_reg = mapped;
                        CallFrameInstruction::CfaRegister(mapped)
                    } else {
                        continue; // no instructions
                    }
                }
                FrameLayoutCommand::RegAt { reg, cfa_offset } => {
                    CallFrameInstruction::Offset(map_reg(isa, *reg), *cfa_offset as i32)
                }
            };
            fde.add_instruction(offset, instr);
        }

        table.add_fde(fde);
    }

    Ok(table)
}
