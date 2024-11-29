#![no_std]

/// mod_m bit
const MOD_M: u8 = 0xc0;
/// rm_m bit
const RM_M: u8 = 0x7;
/// base_m bit
const BASE_M: u8 = 0x7;
/// rex_w bit
const REX_W: u8 = 0x8;
/// maximum instruction length for x86
const MAX_INSN_LEN_X86: usize = 15;

#[cfg(target_arch = "x86")]
const MAX_INSN_LEN_X86_32: usize = MAX_INSN_LEN_X86;

const MAX_INSN_LEN_X86_64: usize = MAX_INSN_LEN_X86;

/// error for crate type
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Error {
    invalidinstlen: usize,
}


impl Error {
    pub fn new() -> Self {
        Self{
            invalidinstlen: 0,
        }
    }
}

/// imm / system bit    
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Bits {
    B16,
    B32,
    B64,
}

#[cfg(target_arch = "x86")]
pub(crate) fn max_insn_len() -> usize {
    MAX_INSN_LEN_X86_32
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn max_insn_len() -> usize {
    MAX_INSN_LEN_X86_64
}

/// get insn len
#[inline]
pub(crate) fn insn_len_x86<T>(insn: *const T, bits: Bits) -> Option<i32> {
    let  mut len: i32 = 0;
    let mut twobytes: i32 = 0;
    let  mut has_modrm: i32 = 0;
	let mut operand_bits = Bits::B32;
    let mut addr_bits = bits;
    let mut c: *const u8 = insn as _;
	let mut modrm: u8 = 0;
    let opcode: u8;

    /* prefixes
	//  *
	//  * 0xf0, 0xf2, 0xf3, 0x2e, 0x36
	//  * 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67
	//  */

	// // skip prefixes
    match unsafe { *c } {
        0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 |
        0x3e | 0x26 | 0x64 | 0x65 | 0x66 | 0x67 => {
            if unsafe { *c } == 0x66 {
                operand_bits = Bits::B32;
            } // 16bits operands
            if unsafe { *c } == 0x67 {
                addr_bits = if addr_bits == Bits::B32 {
                     Bits::B16 
                    } else { 
                    Bits::B32 
                };
            } // 16bits addressing (x86-32), 32bits addressing (x86-64)
            c = unsafe { c.add(1) };
            len += 1;
        },

        _ => {
        
        },
    }


    if bits == Bits::B64 && unsafe{*c} & 0xf0 == 0x40 { // x86-64 && REX byte
        if unsafe {*c} & REX_W != 0 {    
            operand_bits = Bits::B64;
        }
        c = unsafe { c.add(1) };
        len += 1;
    }

    // check for 2bytes opcodes (0x0f prefix)
    if unsafe { *c } == 0x0f {
        twobytes += 1;
        c = unsafe { c.add(1) };
        len += 1;
    // check 0x9b prefix
    /* 0x9b prefix is used only by the following 1byte opcodes
	 *
	 * 0xd9 Mod != 11 Reg/Op = 110 or 111
	 * 0xdb ModR/M = 0xe2 or 0xe3
	 * 0xdd Reg/Op = 110 or 111
	 * 0xdf ModR/M = 0xe0
	 */  
    /* 2bytes opcodes that they *don't* use ModR/M byte:
	 *
	 * 0x05 - 0x09, 0x0b, 0x0e,
	 * 0x30 - 0x37, 0x77, 0x80 - 0x8f,
	 * 0xa0 - 0xa2, 0xa8 - 0xaa, 0xb9
	 * 0xc8 - 0xcf
	 */  
    } else if  (unsafe { *c } == 0x9b && 
    ( (unsafe { *(c.add(1)) } == 0xd9 && (unsafe { *(c.add(2)) } & MOD_M) != MOD_M && (unsafe { *(c.add(2))} & 0x30) == 0x30) ||
        (unsafe { *(c.add(1))  } == 0xdb && (unsafe {*(c.add(2)) } == 0xe2 || unsafe { *(c.add(2)) } == 0xe3)) ||
        (unsafe { *(c.add(1))  } == 0xdd && (unsafe { *(c.add(2)) } & 0x30) == 0x30) ||
        (unsafe { *(c.add(1))  } == 0xdf && unsafe { *(c.add(2)) } == 0xe0)
    )) 
    {
        

        c = unsafe { c.add(1) };
        len += 1;
    }

    opcode = unsafe { *(c.add(1)) };
	len += 1;

	/* 1byte opcodes that use ModR/M byte:
	 *
	 * 0x00 - 0x03, 0x08 - 0x0b,
	 * 0x10 - 0x13, 0x18 - 0x1b,
	 * 0x20 - 0x23, 0x28 - 0x2b,
	 * 0x30 - 0x33, 0x38 - 0x3b,
	 * 0x62, 0x63, 0x69, 0x6b,
	 * 0x80 - 0x8f, 0xc0, 0xc1,
	 * 0xc4 - 0xc7,
	 * 0xd0 - 0xd3, 0xd8 - 0xdf
	 * 0xf6, 0xf7, 0xfe, 0xff
	 */
    if twobytes == 0 && 
    ((opcode & 0xf4) == 0 || (opcode & 0xf4) == 0x10 ||
    (opcode & 0xf4) == 0x20 || (opcode & 0xf4) == 0x30 ||
    opcode == 0x62 || opcode == 0x63 || opcode == 0x69 || opcode == 0x6b ||
    (opcode & 0xf0) == 0x80 || opcode == 0xc0 || opcode == 0xc1 ||
    (opcode & 0xfc) == 0xc4 || (opcode & 0xfc) == 0xd0 ||
    (opcode & 0xf8) == 0xd8 || opcode == 0xf6 || opcode == 0xf7 ||
    opcode == 0xfe || opcode == 0xff) {
        has_modrm = 1;
    }
	/* 2bytes opcodes that they *don't* use ModR/M byte:
	 *
	 * 0x05 - 0x09, 0x0b, 0x0e,
	 * 0x30 - 0x37, 0x77, 0x80 - 0x8f,
	 * 0xa0 - 0xa2, 0xa8 - 0xaa, 0xb9
	 * 0xc8 - 0xcf
	 */
    if twobytes !=0 {
        if  !((opcode >= 0x05 && opcode <= 0x09) || opcode == 0x0b ||
        opcode == 0x0e || (opcode & 0xf8) == 0x30 || opcode == 0x77 ||
        (opcode & 0xf0) == 0x80 || (opcode >= 0xa0 && opcode <= 0xa2) ||
        (opcode >= 0xa8 && opcode <= 0xaa) || (opcode & 0xf8) == 0xc8 ||
        opcode == 0xb9) {
            has_modrm = 1;
        }
        // 3bytes opcodes
        if opcode == 0x38 || opcode == 0x3a {
            c = unsafe { c.add(1) };
            len += 1;
		}
        // 3DNow! opcode
        if opcode ==0x0f {
            len += 1;
        }

    }

    if has_modrm != 0 {
        len += 1;
        modrm = unsafe { *(c.add(1)) };
        assert!(true, "{}", modrm);
        if addr_bits != Bits::B16 && (modrm & (MOD_M | RM_M)) == 5  {// Mod = 00 R/M = 101
            len += 4;
        }    
        if addr_bits == Bits::B16 && (modrm & (MOD_M | RM_M)) == 6 {// Mod = 00 R/M = 110 and 16bits addressing
            len += 2;
        }    
        if (modrm & MOD_M) == 0x40 { // Mod = 01
            len += 1;
        }    
        if (modrm & MOD_M) == 0x80 {// Mod = 10
           match addr_bits {
               Bits::B16 => {
                    len += 2;
               },
               _ => {
                    len += 4;
               },
           }
        }
        // check SIB byte
        if addr_bits != Bits::B16 && (modrm & MOD_M) != MOD_M && (modrm & RM_M) == 4 { // if it has SIB
            len += 1;
            if (modrm & MOD_M) == 0 && (unsafe { *c } & BASE_M) == 5 {// Mod = 00   SIB Base = 101
                len += 4;
            }    
            c = unsafe { c.add(1) };
            let _ = c;
        }
    }
    /* Immediate operands
	 *
	 * 1byte opcode list:
	 *
	 * imm8 (1 byte)
	 *
	 * 0x04, 0x0c, 0x14, 0x1c, 0x24, 0x2c, 0x34, 0x3c, 0x6a, 0x6b, 0x70 - 0x7f,
	 * 0x80, 0x82, 0x83, 0xa8, 0xb0 - 0xb7, 0xc0, 0xc1, 0xc6, 0xcd, 0xd4,
	 * 0xd5, 0xe0 - 0xe7, 0xeb, 0xf6 (Reg/Op = 000 or Reg/Op = 001)
	 *
	 * imm16 (2 bytes)
	 *
	 * 0xc2, 0xca
	 *
	 * imm16/32 (2 bytes if operand_bits == __b16 else 4 bytes)
	 *
	 * 0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d, 0x68, 0x69, 0x81, 0xa9
	 * 0xc7, 0xe8, 0xe9
	 *
	 * imm16/32/64 (2 bytes if operand_bits == __b16, 4 bytes if __b32, 8 bytes if __b64)
	 *
	 * 0xb8 - 0xbf, 0xf7 (Reg/Op = 000 or Reg/Op = 001)
	 *
	 * moffs (2 bytes if addr_bits == __b16, 4 bytes if __b32, 8 bytes if __b64)
	 *
	 * 0xa0, 0xa1, 0xa2, 0xa3
	 *
	 * others
	 *
	 * 0xea, 0x9a: imm16 + imm16/32
	 * 0xc8: imm16 + imm8
	 *
	 *
	 * 2bytes opcode list:
	 *
	 * imm8 (1 byte)
	 *
	 * 0x70 - 0x73, 0xa4, 0xac, 0xba, 0xc2, 0xc4 - 0xc6
	 *
	 * imm16/32 (2 bytes if operand_bits == __b16 else 4 bytes)
	 *
	 * 0x80 - 0x8f
	 *
	 *
	 * all 3bytes opcodes with 0x3a prefix have imm8
	 */
    if twobytes == 0 {
        // imm8
        if ((opcode & 7) == 4 && (opcode & 0xf0) <= 0x30) ||
        opcode == 0x6a || opcode == 0x6b || (opcode & 0xf0) == 0x70 ||
        opcode == 0x80 || opcode == 0x82 || opcode == 0x83 ||
        opcode == 0xa8 || (opcode & 0xf8) == 0xb0 || opcode == 0xc0 ||
        opcode == 0xc1 || opcode == 0xc6 || opcode == 0xcd ||
        opcode == 0xd4 || opcode == 0xd5 || (opcode & 0xf8) == 0xe0 ||
        opcode == 0xeb || (opcode == 0xf6 && (modrm & 0x30) == 0) {
            len += 1;
        }

        // imm16
        if opcode == 0xc2 || opcode == 0xca{
            len += 2;
        }
        // imm16/32
        if ((opcode & 7) == 5 && (opcode & 0xf0) <= 0x30) ||
            opcode == 0x68 || opcode == 0x69 || opcode == 0x81 ||
            opcode == 0xa9 || opcode == 0xc7 || opcode == 0xe8 ||
            opcode == 0xe9 {
                match operand_bits {
                    Bits::B16 =>{
                        len += 2;
                    },
                    _ => {
                        len += 4;
                    },
                }
        }
        // imm16/32/64
        if (opcode & 0xf8) == 0xb8 || (opcode == 0xf7 && (modrm & 0x30) == 0) {
            match operand_bits {
                Bits::B16 => {
                    len += 2;
                },
                Bits::B32 => {
                    len += 4;
                },
                _ => {
                    len += 8;
                },
            }
        }
        // moffs
        if (opcode & 0xfc) == 0xa0 {
            match addr_bits {
                Bits::B16 => {
                    len += 2;
                },
                Bits::B32 => {
                    len += 4;
                },
                _ => {
                    len += 8;
                },
            }
        }
        // others
        if opcode == 0xea || opcode == 0x9a {
            len +=2;
            match operand_bits {
                Bits::B16 =>{
                    len += 2;
                },
                _ => {
                    len += 4;
                },
            }

        }    
        if opcode == 0xc8{
            len += 3;
        }    

    }else { // 2bytes opcodes
        if (opcode & 0xfc) == 0x70 || opcode == 0xa4 ||
        opcode == 0xac || opcode == 0xba || opcode == 0xc2 ||
        (opcode >= 0xc4 && opcode <= 0xc6) {
            len += 1;
        }
        // imm16/32
        if (opcode & 0xf0) == 0x80 {
            match operand_bits {
                Bits::B16 =>{
                    len += 2;
                },
                _ => {
                    len += 4;
                },
            }
        }
        // 3bytes opcodes with 0x3a prefix
        if opcode == 0x3a {
            len += 1;
        }    

    }
    // wrong length
    if len >  max_insn_len() as _ {
        len = 1;
    }

    assert!(true, "{}" ,opcode);
    Some(len)
}

///*==============================================================================*/
///*                            获取32位指令长度                                  */
////*==============================================================================*/
#[cfg(target_arch = "x86")]
pub fn arch_insn_len<T>(insn: *const T) -> Result<i32, Error> {
    match insn_len_x86(insn, Bits::B32) {
        Some(len) => return Ok(len),
        None => Err(Error::new()),
    }
}

///*==============================================================================*/
///*                            获取32位指令长度                                  */
///*==============================================================================*/
#[cfg(target_arch = "x86_64")]
pub fn arch_insn_len_x86<T>(insn: *const T) -> Result<i32, Error> {
	match insn_len_x86(insn, Bits::B64) {
        Some(len) => return Ok(len),
        None => Err(Error::new()),
    }
}



/// test
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        qwb();
        let results = [0x48, 0x83, 0xEC, 0x28, 0xE8, 0x0B, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xE9, 0x7A, 0xFE, 0xFF, 0xFF,  0xcc, 0xcc];
        //let mut result= qwb as *const () as *const u8;
        let result = results.as_ptr() as *const u8;
        let mut b = 0;
        while b < 20 {
            let len = arch_insn_len_x86(unsafe { result.add(b as _) });
            match len {
                Ok(len) => {
                    b += len;
                    if b > 20 {
                        break;
                    }
                },
                Err(_) => {
                    b = 0;
                    break
                },
            }
            
        
        }
        assert_eq!(20, b);
        assert_eq!(results,  [0x48, 0x83, 0xEC, 0x28, 0xE8, 0x0B, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xE9, 0x7A, 0xFE, 0xFF, 0xFF,  0xcc, 0xcc])
    }
}


pub fn qwb () {
    assert_eq!(3, "qwb".len());
}
