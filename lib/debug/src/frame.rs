#![allow(non_upper_case_globals)]

use cranelift_codegen::isa::{CallConv, RegUnit, TargetIsa};
use cranelift_entity::EntityRef;
use cranelift_wasm::DefinedFuncIndex;
use std::collections::HashMap;
use std::vec::Vec;
use wasmtime_environ::{FrameLayoutCommand, FrameLayouts};

use gimli::write::{
    Address, CallFrameInstruction, CommonInformationEntry as CIEEntry, Error,
    FrameDescriptionEntry as FDEEntry, Writer,
};
use gimli::{Register, X86_64};

pub struct DebugFrameTable {
    pub entries: Vec<CIEEntry>,
}

impl DebugFrameTable {
    pub fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
        for cie in self.entries.iter() {
            cie.write(writer)?;
        }
        Ok(())
    }
}

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
) -> Result<DebugFrameTable, Error> {
    assert!(isa.name() == "x86");
    // Expecting all function with System V prologue
    for l in layouts.values() {
        assert!(
            l.call_conv == CallConv::Fast
                || l.call_conv == CallConv::Cold
                || l.call_conv == CallConv::SystemV
        );
    }

    let address_size = isa.pointer_bytes();
    let mut cie = CIEEntry::new();
    cie.version = 4;
    cie.address_size = address_size;
    cie.code_alignment_factor = 1;
    cie.data_alignment_factor = -8;
    cie.return_address_register = X86_64::RA;
    cie.add_initial_instruction(CallFrameInstruction::DefCfa {
        register: X86_64::RSP,
        offset: 8,
    });
    cie.add_initial_instruction(CallFrameInstruction::Offset {
        register: X86_64::RA,
        factored_offset: 1,
    });

    for (i, f) in funcs.into_iter().enumerate() {
        let mut cfa_def_reg = X86_64::RSP;
        let mut cfa_def_offset = 8u64;

        let f_len = f.1 as u64;
        let mut fde = FDEEntry::new();
        fde.initial_location = Address::Relative {
            symbol: i,
            addend: 0,
        };
        fde.address_range = f_len;

        let layout = &layouts[DefinedFuncIndex::new(i)];
        for cmd in layout.commands.into_iter() {
            let instr = match cmd {
                FrameLayoutCommand::MoveLocationBy(delta) => CallFrameInstruction::AdvanceLoc {
                    delta: *delta as u32,
                },
                FrameLayoutCommand::CallFrameAddressAt { reg, offset } => {
                    let mapped = map_reg(isa, *reg);
                    let offset = (*offset) as u64;
                    if mapped != cfa_def_reg && offset != cfa_def_offset {
                        cfa_def_reg = mapped;
                        cfa_def_offset = offset;
                        CallFrameInstruction::DefCfa {
                            register: mapped,
                            offset,
                        }
                    } else if offset != cfa_def_offset {
                        cfa_def_offset = offset;
                        CallFrameInstruction::DefCfaOffset { offset }
                    } else if mapped != cfa_def_reg {
                        cfa_def_reg = mapped;
                        CallFrameInstruction::DefCfaRegister { register: mapped }
                    } else {
                        continue; // no instructions
                    }
                }
                FrameLayoutCommand::RegAt { reg, cfa_offset } => {
                    assert!(cfa_offset % -8 == 0);
                    let factored_offset = (cfa_offset / -8) as u64;
                    let mapped = map_reg(isa, *reg);
                    CallFrameInstruction::Offset {
                        register: mapped,
                        factored_offset,
                    }
                }
            };
            fde.add_instruction(instr);
        }

        cie.add_fde_entry(fde);
    }

    let table = DebugFrameTable { entries: vec![cie] };
    Ok(table)
}
