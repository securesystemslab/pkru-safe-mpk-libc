// MIT License
// mpk/src/lib.rs - PKRU-Safe
//
// Copyright 2018 Paul Kirth
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE

#![never_gate]
#![feature(asm)]
#![feature(exclusive_range_pattern)]

extern crate errno;
extern crate libc;

use errno::{errno};

use libc::{c_void, size_t, syscall, SYS_pkey_alloc, SYS_pkey_free,
           SYS_pkey_mprotect, SYS_exit};

pub fn pkey_read() -> u32 {
    let result: u32;
    unsafe{asm!(".byte 0x0f, 0x01, 0xee" : "={eax}"(result) : "{ecx}"(0) : "edx");}
    //unsafe { asm!("rdpkru":  "=eax"(result) : "ecx"(0) : "edx": "volatile") }
    return result;
}

pub fn pkey_write(pkru: u32) {
    let eax = pkru;
    let ecx = 0;
    let edx = 0;

    unsafe { asm!("wrpkru"::"{eax}"(eax), "{ecx}"(ecx), "{edx}"(edx)) }
}

pub fn pkey_get(key: i32) -> Result<u32, &'static str> {
    match key {
        0..15 => {
            let pkru = pkey_read();
            Ok((pkru >> (2 * key)) & 3)
        }
        _ => Err("Invalid PKEY"),
    }
}

pub fn pkey_set(pkey: i32, rights: u32) -> Result<(), &'static str> {
    match pkey {
        0..15 => {
            let mask: u32 = 3 << (2 * pkey);
            let mut pkru = pkey_read();
            pkru = (pkru & !mask) | (rights << (2 * pkey));
            pkey_write(pkru);
            Ok(())
        }
        _ => Err("Invalid PKEY"),
    }
}

pub fn pkey_set_panic(pkey: i32, rights: u32) {
    match pkey {
        0..15 => {
            let mask: u32 = 3 << (2 * pkey);
            let mut pkru = pkey_read();
            pkru = (pkru & !mask) | (rights << (2 * pkey));
            pkey_write(pkru);
        }
        _ => panic!("Invalid PKEY"),
    }
}

#[inline(always)]
pub fn pkrusafe_enter(){
    let eax = 0x0;
    let ecx = 0;
    let edx = 0;

    unsafe {
        asm!("wrpkru"::"{eax}"(eax), "{ecx}"(ecx), "{edx}"(edx));
        asm!("cmpl $$0x0, %eax");
        asm!("je 2f");
        syscall(SYS_exit);
        asm!("2:");
    }
}

#[inline(always)]
pub fn pkrusafe_exit(){
    let eax = 0xc;
    let ecx = 0;
    let edx = 0;
    let target: u32;

    unsafe {
        asm!("wrpkru"::"{eax}"(eax), "{ecx}"(ecx), "{edx}"(edx));
        asm!("cmpl $$0xc, %eax");
        asm!("je 1f");
        syscall(SYS_exit);
        asm!("1:");
    }
}

pub fn pkey_mprotect(addr: *mut c_void, len: size_t, prot: i32, pkey: i32) -> Result<(), i32> {
    let ret: i64;
    unsafe {
        ret = syscall(SYS_pkey_mprotect, addr, len, prot, pkey);
    }
    match ret {
        0 => Ok(()),
        -1 => Err(errno().0),
        _ => Err(errno().0),
    }
}

pub fn pkey_alloc() -> i32 {
    unsafe { syscall(SYS_pkey_alloc, 0, 0) as i32 }
}

pub fn pkey_free(pkey: u32) -> i32 {
    unsafe { syscall(SYS_pkey_free, pkey) as i32 }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
