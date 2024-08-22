use super::TransformError;
use super::address_transform::AddressTransform;
use crate::debug::Reader;
use anyhow::Error;
use gimli::{DebugLineOffset, UnitRef, write};

pub(crate) fn clone_line_program(
    unit: UnitRef<Reader<'_>>,
    comp_name: Option<Reader<'_>>,
    addr_tr: &AddressTransform,
    out_encoding: gimli::Encoding,
    out_strings: &mut write::StringTable,
    out_line_strings: &mut write::LineStringTable,
) -> Result<(write::LineProgram, DebugLineOffset, Vec<write::FileId>, u64), Error> {
    let Some(program) = unit.line_program.clone() else {
        return Err(TransformError("Valid line program not found").into());
    };

    let offset = program.header().offset();
    let line_encoding = program.header().line_encoding();
    let mut transform = write::LineConvert::new(
        unit.dwarf,
        program,
        comp_name,
        out_encoding,
        line_encoding,
        out_line_strings,
        out_strings,
    )?;

    while let Some(write::LineConvertSequence {
        start,
        rows: saved_rows,
        ..
    }) = transform.read_sequence()?
    {
        let Some(start) = start else {
            continue;
        };
        if start == 0 {
            continue;
        }
        let Some(index) = addr_tr.find_func_index(start) else {
            // Some non-existent address found.
            continue;
        };
        let Some(map) = addr_tr.map().get(index) else {
            continue; // no code generated
        };
        let symbol = map.symbol;
        let base_addr = map.offset;
        transform.begin_sequence(Some(write::Address::Symbol { symbol, addend: 0 }));
        // TODO track and place function declaration line here
        let mut last_address = None;
        for addr_map in map.addresses.iter() {
            let Some(wasm_offset) = addr_map.wasm.checked_sub(start) else {
                continue;
            };
            let mut saved_row =
                match saved_rows.binary_search_by_key(&wasm_offset, |i| i.address_offset) {
                    Ok(i) => saved_rows[i],
                    Err(i) => {
                        if i > 0 {
                            saved_rows[i - 1]
                        } else {
                            continue;
                        }
                    }
                };
            // Ignore duplicates
            if Some(saved_row.address_offset) != last_address {
                let address_offset = if last_address.is_none() {
                    // Extend first entry to the function declaration
                    // TODO use the function declaration line instead
                    0
                } else {
                    (addr_map.generated - base_addr) as u64
                };
                last_address = Some(saved_row.address_offset);
                saved_row.address_offset = address_offset;
                transform.generate_row(saved_row);
            }
        }
        transform.end_sequence(map.len as u64);
    }
    let (out_program, files) = transform.program();
    Ok((out_program, offset, files, 0))
}
