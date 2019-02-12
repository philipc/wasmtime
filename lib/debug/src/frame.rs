#![allow(non_upper_case_globals)]

use cranelift_codegen::isa::{CallConv, RegUnit, TargetIsa};
use cranelift_entity::EntityRef;
use cranelift_wasm::DefinedFuncIndex;
use std::collections::HashMap;
use std::vec::Vec;
use wasmtime_environ::{FrameLayoutCommand, FrameLayouts};

use gimli::write::{EndianVec, Error};
use gimli::{LittleEndian, Register, X86_64};

trait Writer: gimli::write::Writer<Endian = LittleEndian> {}
impl Writer for EndianVec<LittleEndian> {}

enum CallFrameInstruction {
    AdvanceLoc {
        delta: u32,
    },
    DefCfa {
        register: Register,
        offset: u64,
    },
    DefCfaRegister {
        register: Register,
    },
    DefCfaOffset {
        offset: u64,
    },
    Offset {
        register: Register,
        factored_offset: u64,
    },
}

impl CallFrameInstruction {
    fn write(&self, writer: &mut Writer) -> Result<(), Error> {
        match *self {
            CallFrameInstruction::AdvanceLoc { delta } => {
                assert!(delta < 0x40);
                // DW_CFA_advance_loc
                writer.write_u8(0x40 | delta as u8)?;
            }
            CallFrameInstruction::DefCfa { register, offset } => {
                //  DW_CFA_def_cfa
                writer.write_u8(0x0c)?;
                writer.write_uleb128(register.0 as u64)?;
                writer.write_uleb128(offset)?;
            }
            CallFrameInstruction::DefCfaRegister { register } => {
                // DW_CFA_def_cfa_register
                writer.write_u8(0x0d)?;
                writer.write_uleb128(register.0 as u64)?;
            }
            CallFrameInstruction::DefCfaOffset { offset } => {
                //   DW_CFA_def_cfa_offset
                writer.write_u8(0x0e)?;
                writer.write_uleb128(offset)?;
            }
            CallFrameInstruction::Offset {
                register,
                factored_offset,
            } => {
                assert!(register.0 < 0x40);
                //    DW_CFA_offset: r at cfa-8
                writer.write_u8(0x80 | register.0 as u8)?;
                writer.write_uleb128(factored_offset)?;
            }
        }
        Ok(())
    }
}

fn pad_with_nop(writer: &mut Writer, len: usize, align: u8) -> Result<(), Error> {
    const DW_CFA_nop: u8 = 0;
    let tail_len = (!len + 1) & (align as usize - 1);
    for _ in 0..tail_len {
        writer.write_u8(DW_CFA_nop)?;
    }
    Ok(())
}

struct FDEEntry {
    pub initial_location: u64,
    pub address_range: u64,
    pub instructions: Vec<CallFrameInstruction>,
}

impl FDEEntry {
    fn write(
        &self,
        writer: &mut Writer,
        cie_ptr: u32,
        address_size: u8,
        relocs: &mut Vec<usize>,
    ) -> Result<(), Error> {
        // Write FDE, patch len at the end
        let pos = writer.len();
        writer.write_u32(0)?;

        writer.write_u32(cie_ptr)?;
        // <--- reloc here to function sym
        relocs.push(writer.len());
        assert!(address_size == 8);
        writer.write_u64(/* initial_location */ self.initial_location)?;
        writer.write_u64(/* address_range */ self.address_range)?;

        for instr in self.instructions.iter() {
            instr.write(writer)?;
        }

        let entry_len = writer.len() - pos;
        pad_with_nop(writer, entry_len, address_size)?;

        let entry_len = (writer.len() - pos) as u32;
        writer.write_u32_at(pos, entry_len - ::std::mem::size_of::<u32>() as u32)?;

        Ok(())
    }
}

struct CIEEntry {
    pub version: u8,
    pub aug: &'static str,
    pub address_size: u8,
    pub segment_selector_size: u8,
    pub code_alignment_factor: u64,
    pub data_alignment_factor: i64,
    pub return_address_register: Register,
    pub aug_data: Vec<u8>,
    pub initial_instructions: Vec<CallFrameInstruction>,
    pub fde_entries: Vec<FDEEntry>,
}

impl CIEEntry {
    fn write(&self, writer: &mut Writer, relocs: &mut Vec<usize>) -> Result<(), Error> {
        // Write CIE, patch len at the end
        let pos = writer.len();
        writer.write_u32(0)?;
        const CIE_ID: u32 = 0xFFFFFFFF;
        writer.write_u32(CIE_ID)?;
        writer.write_u8(/* version: u8 */ self.version)?;
        assert!(self.aug.len() == 0);
        writer.write_u8(/* augumentation: utf8z = [0] */ 0x00)?;
        writer.write_u8(/* address_size [v4]: u8 */ self.address_size)?;
        writer.write_u8(
            /* segment_selector_size [v4]: u8 */ self.segment_selector_size,
        )?;
        writer.write_uleb128(
            /* code_alignment_factor: uleb128 */ self.code_alignment_factor,
        )?;
        writer.write_sleb128(
            /* data_alignment_factor: sleb128 */ self.data_alignment_factor,
        )?;
        writer.write_uleb128(
            /* return_address_register [v3]: uleb128 */
            self.return_address_register.0.into(),
        )?;

        if self.aug.len() > 0 {
            writer.write(&self.aug_data)?;
        }

        for instr in self.initial_instructions.iter() {
            instr.write(writer)?;
        }

        let entry_len = writer.len() - pos;
        pad_with_nop(writer, entry_len, self.address_size)?;

        let entry_len = (writer.len() - pos) as u32;
        writer.write_u32_at(pos, entry_len - ::std::mem::size_of::<u32>() as u32)?;

        let cie_ptr = pos as u32;
        for fde in self.fde_entries.iter() {
            fde.write(writer, cie_ptr, self.address_size, relocs)?;
        }
        Ok(())
    }
}

struct DebugFrameTable {
    pub entries: Vec<CIEEntry>,
}

impl DebugFrameTable {
    fn write(&self, writer: &mut dyn Writer, relocs: &mut Vec<usize>) -> Result<(), Error> {
        for cie in self.entries.iter() {
            cie.write(writer, relocs)?;
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
) -> Result<(Vec<u8>, Vec<usize>), Error> {
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
    let mut cie = CIEEntry {
        version: 4,
        aug: "",
        address_size,
        segment_selector_size: 0,
        code_alignment_factor: 1,
        data_alignment_factor: -8,
        return_address_register: X86_64::RA,
        aug_data: vec![],
        initial_instructions: vec![
            CallFrameInstruction::DefCfa {
                register: X86_64::RSP,
                offset: 8,
            },
            CallFrameInstruction::Offset {
                register: X86_64::RA,
                factored_offset: 1,
            },
        ],
        fde_entries: Vec::new(),
    };

    for (i, f) in funcs.into_iter().enumerate() {
        let mut cfa_def_reg = X86_64::RSP;
        let mut cfa_def_offset = 8u64;
        let mut instructions = Vec::new();

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
            instructions.push(instr);
        }

        let f_len = f.1 as u64;
        let fde = FDEEntry {
            initial_location: 0,
            address_range: f_len,
            instructions,
        };
        cie.fde_entries.push(fde);
    }

    let table = DebugFrameTable { entries: vec![cie] };

    let mut result = EndianVec::new(LittleEndian);
    let mut relocs = Vec::new();
    table.write(&mut result, &mut relocs)?;

    Ok((result.into_vec(), relocs))
}
