//! System V ABI unwind information.

use alloc::vec::Vec;
use gimli::write::{Address, FrameDescriptionEntry};
use thiserror::Error;

#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Serialize};

type Register = u16;

/// Enumerate the errors possible in mapping Cranelift registers to their DWARF equivalent.
#[allow(missing_docs)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum RegisterMappingError {
    #[error("unable to find bank for register info")]
    MissingBank,
    #[error("register mapping is currently only implemented for x86_64")]
    UnsupportedArchitecture,
    #[error("unsupported register bank: {0}")]
    UnsupportedRegisterBank(&'static str),
}

// This mirrors gimli's CallFrameInstruction, but is serializable
// TODO: if gimli ever adds serialization support, remove this type
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub(crate) enum CallFrameInstruction {
    Cfa(Register, i32),
    CfaRegister(Register),
    CfaOffset(i32),
    Restore(Register),
    Undefined(Register),
    SameValue(Register),
    Offset(Register, i32),
    ValOffset(Register, i32),
    Register(Register, Register),
    RememberState,
    RestoreState,
    ArgsSize(u32),
}

impl Into<gimli::write::CallFrameInstruction> for CallFrameInstruction {
    fn into(self) -> gimli::write::CallFrameInstruction {
        use gimli::{
            write::CallFrameInstruction,
            Register,
        };

        match self {
            Self::Cfa(reg, offset) => CallFrameInstruction::Cfa(Register(reg), offset),
            Self::CfaRegister(reg) => CallFrameInstruction::CfaRegister(Register(reg)),
            Self::CfaOffset(offset) => CallFrameInstruction::CfaOffset(offset),
            Self::Restore(reg) => CallFrameInstruction::Restore(Register(reg)),
            Self::Undefined(reg) => CallFrameInstruction::Undefined(Register(reg)),
            Self::SameValue(reg) => CallFrameInstruction::SameValue(Register(reg)),
            Self::Offset(reg, offset) => CallFrameInstruction::Offset(Register(reg), offset),
            Self::ValOffset(reg, offset) => CallFrameInstruction::ValOffset(Register(reg), offset),
            Self::Register(reg1, reg2) => {
                CallFrameInstruction::Register(Register(reg1), Register(reg2))
            }
            Self::RememberState => CallFrameInstruction::RememberState,
            Self::RestoreState => CallFrameInstruction::RestoreState,
            Self::ArgsSize(size) => CallFrameInstruction::ArgsSize(size),
        }
    }
}

/// Represents unwind information for a single System V ABI function.
///
/// This representation is not ISA specific.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct UnwindInfo {
    instructions: Vec<(u32, CallFrameInstruction)>,
    len: u32,
}

impl UnwindInfo {
    pub(crate) fn new(instructions: Vec<(u32, CallFrameInstruction)>, len: u32) -> Self {
        Self { instructions, len }
    }

    /// Converts the unwind information into a `FrameDescriptionEntry`.
    pub fn to_fde(&self, address: Address) -> gimli::write::FrameDescriptionEntry {
        let mut fde = FrameDescriptionEntry::new(address, self.len);

        for (offset, inst) in &self.instructions {
            fde.add_instruction(*offset, inst.clone().into());
        }

        fde
    }
}
