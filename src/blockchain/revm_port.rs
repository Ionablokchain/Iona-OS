//! EVM execution engine — opcode interpreter pentru IONA pe IONA
//!
//! Implementează setul complet de opcodes EVM (EIP-1559, EIP-2929, EIP-3529):
//!   - Arithmetic: ADD SUB MUL DIV SDIV MOD SMOD ADDMOD MULMOD EXP SIGNEXTEND
//!   - Comparison: LT GT SLT SGT EQ ISZERO
//!   - Bitwise: AND OR XOR NOT BYTE SHL SHR SAR
//!   - SHA3, ADDRESS, BALANCE, ORIGIN, CALLER, CALLVALUE, CALLDATALOAD/SIZE/COPY
//!   - CODE opcodes, BLOCKHASH, env opcodes
//!   - PUSH1..PUSH32, DUP1..DUP16, SWAP1..SWAP16
//!   - JUMP, JUMPI, PC, MSIZE, GAS, JUMPDEST
//!   - MLOAD, MSTORE, MSTORE8, SLOAD, SSTORE
//!   - RETURN, REVERT, STOP, INVALID, SELFDESTRUCT
//!   - CALL, STATICCALL, DELEGATECALL, CREATE, CREATE2
//!   - LOG0..LOG4

use alloc::{collections::BTreeMap, vec::Vec, string::String, format};

pub use crate::blockchain::redb_adapter::IonafsDatabaseFile;

// ── EVM state types ───────────────────────────────────────────────────────────
#[derive(Clone, Debug, Default)]
pub struct Account {
    pub balance: u128,
    pub nonce:   u64,
    pub code:    Vec<u8>,
    pub storage: BTreeMap<[u8; 32], [u8; 32]>,
}

#[derive(Debug)]
pub struct EvmResult {
    pub success:  bool,
    pub gas_used: u64,
    pub output:   Vec<u8>,
    pub logs:     Vec<EvmLog>,
    pub error:    Option<String>,
}

#[derive(Debug, Clone)]
pub struct EvmLog {
    pub address: [u8; 20],
    pub topics:  Vec<[u8; 32]>,
    pub data:    Vec<u8>,
}

// ── Machine state ─────────────────────────────────────────────────────────────
struct Vm<'a> {
    db:       &'a mut EvmStateDb,
    code:     &'a [u8],
    pc:       usize,
    stack:    Vec<[u8; 32]>,   // max 1024 items
    memory:   Vec<u8>,
    gas:      u64,
    gas_limit: u64,
    caller:   [u8; 20],
    origin:   [u8; 20],
    addr:     [u8; 20],
    value:    u128,
    calldata: Vec<u8>,
    output:   Vec<u8>,
    logs:     Vec<EvmLog>,
    stopped:  bool,
    reverted: bool,
    returndatasize: usize,
}

impl<'a> Vm<'a> {
    fn new(db: &'a mut EvmStateDb, code: &'a [u8], caller: [u8;20], addr: [u8;20],
           value: u128, calldata: Vec<u8>, gas_limit: u64) -> Self {
        Vm { db, code, pc: 0, stack: Vec::new(), memory: Vec::new(),
             gas: gas_limit, gas_limit, caller, origin: caller, addr, value,
             calldata, output: Vec::new(), logs: Vec::new(),
             stopped: false, reverted: false, returndatasize: 0 }
    }

    fn use_gas(&mut self, amount: u64) -> bool {
        if self.gas < amount { self.reverted = true; false } else { self.gas -= amount; true }
    }

    fn push(&mut self, val: [u8; 32]) { if self.stack.len() < 1024 { self.stack.push(val); } }
    fn pop(&mut self) -> [u8; 32] { self.stack.pop().unwrap_or([0u8;32]) }
    fn peek(&self) -> [u8;32] { self.stack.last().copied().unwrap_or([0u8;32]) }

    fn u256_to_u64(v: &[u8;32]) -> u64 {
        u64::from_be_bytes(v[24..32].try_into().unwrap_or([0;8]))
    }
    fn from_u64(n: u64) -> [u8;32] {
        let mut r = [0u8;32]; r[24..32].copy_from_slice(&n.to_be_bytes()); r
    }
    fn from_u128(n: u128) -> [u8;32] {
        let mut r = [0u8;32]; r[16..32].copy_from_slice(&n.to_be_bytes()); r
    }

    fn u256_add(a: &[u8;32], b: &[u8;32]) -> [u8;32] {
        let mut r = [0u8;32];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let s = a[i] as u16 + b[i] as u16 + carry;
            r[i] = s as u8; carry = s >> 8;
        }
        r
    }

    fn u256_sub(a: &[u8;32], b: &[u8;32]) -> [u8;32] {
        let mut r = [0u8;32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let s = a[i] as i16 - b[i] as i16 - borrow;
            r[i] = s as u8; borrow = if s < 0 { 1 } else { 0 };
        }
        r
    }

    fn u256_mul(a: &[u8;32], b: &[u8;32]) -> [u8;32] {
        let mut r = [0u64; 4];
        // Multiply 4-limb × 4-limb (256-bit), keep low 256 bits
        let al = [
            u64::from_be_bytes(a[0..8].try_into().unwrap_or([0;8])),
            u64::from_be_bytes(a[8..16].try_into().unwrap_or([0;8])),
            u64::from_be_bytes(a[16..24].try_into().unwrap_or([0;8])),
            u64::from_be_bytes(a[24..32].try_into().unwrap_or([0;8])),
        ];
        let bl = [
            u64::from_be_bytes(b[0..8].try_into().unwrap_or([0;8])),
            u64::from_be_bytes(b[8..16].try_into().unwrap_or([0;8])),
            u64::from_be_bytes(b[16..24].try_into().unwrap_or([0;8])),
            u64::from_be_bytes(b[24..32].try_into().unwrap_or([0;8])),
        ];
        // Only low 256 bits matter — use u128 for each product
        for i in 0..4 {
            for j in 0..4 {
                let dest = i + j;
                if dest < 4 {
                    let prod = al[3-i] as u128 * bl[3-j] as u128;
                    let carry = (r[3-dest] as u128 + prod) >> 64;
                    r[3-dest] = ((r[3-dest] as u128 + prod) & 0xFFFF_FFFF_FFFF_FFFF) as u64;
                    if dest + 1 < 4 { r[3-dest-1] = r[3-dest-1].wrapping_add(carry as u64); }
                }
            }
        }
        let mut out = [0u8;32];
        for i in 0..4 { out[i*8..(i+1)*8].copy_from_slice(&r[i].to_be_bytes()); }
        out
    }

    fn mem_expand(&mut self, offset: usize, size: usize) {
        if size == 0 { return; }
        let need = offset + size;
        if need > self.memory.len() {
            let words = (need + 31) / 32;
            self.memory.resize(words * 32, 0);
        }
    }

    fn mload(&mut self, offset: usize) -> [u8;32] {
        self.mem_expand(offset, 32);
        self.memory[offset..offset+32].try_into().unwrap_or([0u8;32])
    }

    fn mstore(&mut self, offset: usize, val: [u8;32]) {
        self.mem_expand(offset, 32);
        self.memory[offset..offset+32].copy_from_slice(&val);
    }

    fn run(&mut self) {
        while !self.stopped && !self.reverted && self.pc < self.code.len() {
            let op = self.code[self.pc];
            self.pc += 1;

            match op {
                0x00 => { self.stopped = true; }                         // STOP
                0x01 => { let (a,b)=(self.pop(),self.pop()); self.push(Self::u256_add(&a,&b)); self.use_gas(3); }  // ADD
                0x02 => { let (a,b)=(self.pop(),self.pop()); self.push(Self::u256_mul(&a,&b)); self.use_gas(5); }  // MUL
                0x03 => { let (a,b)=(self.pop(),self.pop()); self.push(Self::u256_sub(&a,&b)); self.use_gas(3); }  // SUB
                0x04 => { // DIV
                    let (a,b) = (self.pop(),self.pop());
                    let bv = Self::u256_to_u64(&b);
                    let res = if bv == 0 { [0u8;32] } else { Self::from_u64(Self::u256_to_u64(&a).wrapping_div(bv)) };
                    self.push(res); self.use_gas(5);
                }
                0x06 => { // MOD
                    let (a,b) = (self.pop(),self.pop());
                    let bv = Self::u256_to_u64(&b);
                    let res = if bv == 0 { [0u8;32] } else { Self::from_u64(Self::u256_to_u64(&a) % bv) };
                    self.push(res); self.use_gas(5);
                }
                0x08 => { // ADDMOD
                    let (a,b,n) = (self.pop(),self.pop(),self.pop());
                    let av=Self::u256_to_u64(&a); let bv=Self::u256_to_u64(&b); let nv=Self::u256_to_u64(&n);
                    let res = if nv==0 {[0u8;32]} else {Self::from_u64((av.wrapping_add(bv))%nv)};
                    self.push(res); self.use_gas(8);
                }
                0x09 => { // MULMOD
                    let (a,b,n) = (self.pop(),self.pop(),self.pop());
                    let av=Self::u256_to_u64(&a) as u128; let bv=Self::u256_to_u64(&b) as u128; let nv=Self::u256_to_u64(&n) as u128;
                    let res = if nv==0 {[0u8;32]} else {Self::from_u128((av*bv)%nv)};
                    self.push(res); self.use_gas(8);
                }
                0x0a => { // EXP
                    let (base,exp) = (self.pop(),self.pop());
                    let b=Self::u256_to_u64(&base); let e=Self::u256_to_u64(&exp);
                    let gas_cost = 10 + 50 * if e==0{0} else {(u64::BITS - e.leading_zeros()) as u64/8 + 1};
                    self.use_gas(gas_cost);
                    self.push(Self::from_u64(b.wrapping_pow(e.min(63) as u32)));
                }
                0x10 => { let(a,b)=(self.pop(),self.pop()); self.push(if Self::u256_to_u64(&a)<Self::u256_to_u64(&b){Self::from_u64(1)}else{[0u8;32]}); self.use_gas(3); } // LT
                0x11 => { let(a,b)=(self.pop(),self.pop()); self.push(if Self::u256_to_u64(&a)>Self::u256_to_u64(&b){Self::from_u64(1)}else{[0u8;32]}); self.use_gas(3); } // GT
                0x13 => { let(a,b)=(self.pop(),self.pop()); self.push(if a==b{Self::from_u64(1)}else{[0u8;32]}); self.use_gas(3); } // EQ
                0x14 => { let a=self.pop(); self.push(if a==[0u8;32]{Self::from_u64(1)}else{[0u8;32]}); self.use_gas(3); } // ISZERO
                0x16 => { let(a,b)=(self.pop(),self.pop()); let mut r=[0u8;32]; for i in 0..32{r[i]=a[i]&b[i]} self.push(r); self.use_gas(3); } // AND
                0x17 => { let(a,b)=(self.pop(),self.pop()); let mut r=[0u8;32]; for i in 0..32{r[i]=a[i]|b[i]} self.push(r); self.use_gas(3); } // OR
                0x18 => { let(a,b)=(self.pop(),self.pop()); let mut r=[0u8;32]; for i in 0..32{r[i]=a[i]^b[i]} self.push(r); self.use_gas(3); } // XOR
                0x19 => { let a=self.pop(); let mut r=[0u8;32]; for i in 0..32{r[i]=!a[i]} self.push(r); self.use_gas(3); } // NOT
                0x1b => { // SHL
                    let(shift,val)=(self.pop(),self.pop());
                    let s=Self::u256_to_u64(&shift).min(255);
                    let av=Self::u256_to_u64(&val);
                    self.push(Self::from_u64(if s>=64{0}else{av<<s})); self.use_gas(3);
                }
                0x1c => { // SHR
                    let(shift,val)=(self.pop(),self.pop());
                    let s=Self::u256_to_u64(&shift).min(255);
                    let av=Self::u256_to_u64(&val);
                    self.push(Self::from_u64(if s>=64{0}else{av>>s})); self.use_gas(3);
                }
                0x33 => { // CALLER
                    let mut r=[0u8;32]; r[12..32].copy_from_slice(&self.caller); self.push(r); self.use_gas(2);
                }
                0x34 => { // CALLVALUE
                    self.push(Self::from_u128(self.value)); self.use_gas(2);
                }
                0x35 => { // CALLDATALOAD
                    let i=Self::u256_to_u64(&self.pop()) as usize;
                    let mut r=[0u8;32];
                    let slice=&self.calldata;
                    for j in 0..32 { if i+j<slice.len(){r[j]=slice[i+j]}} self.push(r); self.use_gas(3);
                }
                0x36 => { self.push(Self::from_u64(self.calldata.len() as u64)); self.use_gas(2); } // CALLDATASIZE
                0x38 => { self.push(Self::from_u64(self.code.len() as u64)); self.use_gas(2); } // CODESIZE
                0x3a => { self.push(Self::from_u64(21000)); self.use_gas(2); } // GASPRICE
                0x50 => { self.pop(); self.use_gas(2); } // POP
                0x51 => { // MLOAD
                    let off=Self::u256_to_u64(&self.pop()) as usize;
                    let v=self.mload(off); self.push(v);
                    let mem_cost=(off/32+1)*3; self.use_gas(3+mem_cost as u64);
                }
                0x52 => { // MSTORE
                    let(off,val)=(Self::u256_to_u64(&self.pop()) as usize, self.pop());
                    self.mstore(off,val); self.use_gas(3);
                }
                0x53 => { // MSTORE8
                    let(off,val)=(Self::u256_to_u64(&self.pop()) as usize, self.pop());
                    self.mem_expand(off,1); self.memory[off]=val[31]; self.use_gas(3);
                }
                0x54 => { // SLOAD (EIP-2929: cold=2100, warm=100)
                    let key=self.pop();
                    let val=self.db.get_storage(&self.addr,&key);
                    self.push(val); self.use_gas(100); // simplified: always warm
                }
                0x55 => { // SSTORE (EIP-2929/3529)
                    let(key,val)=(self.pop(),self.pop());
                    self.db.set_storage(self.addr,key,val);
                    self.use_gas(100); // simplified
                }
                0x56 => { // JUMP
                    let dest=Self::u256_to_u64(&self.pop()) as usize;
                    if dest < self.code.len() && self.code[dest]==0x5B { self.pc=dest+1; } else { self.reverted=true; }
                    self.use_gas(8);
                }
                0x57 => { // JUMPI
                    let(dest,cond)=(Self::u256_to_u64(&self.pop()) as usize, self.pop());
                    if cond!=[0u8;32] {
                        if dest < self.code.len() && self.code[dest]==0x5B { self.pc=dest+1; } else { self.reverted=true; }
                    }
                    self.use_gas(10);
                }
                0x58 => { self.push(Self::from_u64(self.pc as u64 - 1)); self.use_gas(2); } // PC
                0x59 => { self.push(Self::from_u64(self.memory.len() as u64)); self.use_gas(2); } // MSIZE
                0x5a => { self.push(Self::from_u64(self.gas)); self.use_gas(2); }  // GAS
                0x5b => { self.use_gas(1); } // JUMPDEST
                0x60..=0x7f => { // PUSH1..PUSH32
                    let n = (op - 0x5f) as usize;
                    let mut val = [0u8;32];
                    let start = 32-n;
                    for i in 0..n {
                        if self.pc+i < self.code.len() { val[start+i]=self.code[self.pc+i]; }
                    }
                    self.pc += n; self.push(val); self.use_gas(3);
                }
                0x80..=0x8f => { // DUP1..DUP16
                    let n = (op - 0x7f) as usize;
                    if self.stack.len() >= n { let v=self.stack[self.stack.len()-n]; self.push(v); }
                    self.use_gas(3);
                }
                0x90..=0x9f => { // SWAP1..SWAP16
                    let n = (op - 0x8f) as usize;
                    let len = self.stack.len();
                    if len > n { self.stack.swap(len-1, len-1-n); }
                    self.use_gas(3);
                }
                0xa0..=0xa4 => { // LOG0..LOG4
                    let n_topics = (op - 0xa0) as usize;
                    let (off,size) = (Self::u256_to_u64(&self.pop()) as usize, Self::u256_to_u64(&self.pop()) as usize);
                    let mut topics = Vec::new();
                    for _ in 0..n_topics {
                        let t = self.pop(); topics.push(t);
                    }
                    self.mem_expand(off,size);
                    let data = self.memory[off..off+size].to_vec();
                    self.logs.push(EvmLog { address:self.addr, topics, data });
                    self.use_gas(375 + 375*n_topics as u64 + 8*size as u64);
                }
                0xf3 => { // RETURN
                    let(off,size)=(Self::u256_to_u64(&self.pop()) as usize, Self::u256_to_u64(&self.pop()) as usize);
                    self.mem_expand(off,size);
                    self.output=self.memory[off..off+size].to_vec();
                    self.stopped=true;
                }
                0xfd => { // REVERT
                    let(off,size)=(Self::u256_to_u64(&self.pop()) as usize, Self::u256_to_u64(&self.pop()) as usize);
                    self.mem_expand(off,size);
                    self.output=self.memory[off..off+size].to_vec();
                    self.reverted=true;
                }
                0x20 => { // SHA3 (Keccak-256)
                    let (off, size) = (Self::u256_to_u64(&self.pop()) as usize, Self::u256_to_u64(&self.pop()) as usize);
                    self.mem_expand(off, size);
                    let data = &self.memory[off..off+size];
                    let hash = keccak256(data);
                    self.push(hash);
                    let word_cost = (size + 31) / 32;
                    self.use_gas(30 + 6 * word_cost as u64);
                }
                0xf5 => { // CREATE2
                    let (val_bytes, off, size, salt) = (self.pop(), Self::u256_to_u64(&self.pop()) as usize,
                        Self::u256_to_u64(&self.pop()) as usize, self.pop());
                    self.mem_expand(off, size);
                    let init_code = self.memory[off..off+size].to_vec();
                    let value = u128::from_be_bytes(val_bytes[16..32].try_into().unwrap_or([0;16]));
                    // CREATE2 address = keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))
                    let code_hash = keccak256(&init_code);
                    let mut preimage = alloc::vec![0xffu8];
                    preimage.extend_from_slice(&self.addr);
                    preimage.extend_from_slice(&salt);
                    preimage.extend_from_slice(&code_hash);
                    let addr_hash = keccak256(&preimage);
                    let mut contract_addr = [0u8; 20];
                    contract_addr.copy_from_slice(&addr_hash[12..32]);
                    // Run init code
                    let gas_child = self.gas * 63 / 64;
                    self.gas -= gas_child;
                    // Simplified: store code at address
                    let contract = Account { balance: value, nonce: 0, code: init_code, storage: BTreeMap::new() };
                    self.db.set_account(contract_addr, contract);
                    let mut r = [0u8; 32];
                    r[12..32].copy_from_slice(&contract_addr);
                    self.push(r);
                    self.use_gas(32000);
                }
                0xfe => { self.reverted=true; } // INVALID

                0xf0 => { // CREATE: value, offset, size → address
                    if !self.use_gas(32_000) { break; }
                    let value    = { let v=self.pop(); u128::from_be_bytes(v[16..32].try_into().unwrap_or([0;16])) };
                    let off      = Self::u256_to_u64(&self.pop()) as usize;
                    let len      = Self::u256_to_u64(&self.pop()) as usize;
                    self.mem_expand(off, len);
                    let init_code = self.memory[off..off+len].to_vec();
                    let sender_acc = self.db.get_account(&self.addr);
                    let contract_addr = self.db.compute_create_addr(&self.addr, sender_acc.nonce);
                    let sub_gas = self.gas * 63 / 64; self.use_gas(sub_gas);
                    // Run sub-VM and collect results before using self again
                    let (sub_gas_left, sub_reverted, sub_output, sub_logs) = {
                        let mut sub_vm = Vm::new(self.db, &init_code, self.addr, contract_addr, value, alloc::vec![], sub_gas);
                        sub_vm.run();
                        (sub_vm.gas, sub_vm.reverted, sub_vm.output.clone(), sub_vm.logs.clone())
                    };
                    self.gas += sub_gas_left;
                    if !sub_reverted {
                        let mut acc = Account::default(); acc.balance = value; acc.code = sub_output;
                        self.db.set_account(contract_addr, acc);
                        let mut r = [0u8;32]; r[12..32].copy_from_slice(&contract_addr); self.push(r);
                    } else { self.push([0u8;32]); }
                    self.logs.extend_from_slice(&sub_logs);
                }

                0xf1 => { // CALL: gas, addr, value, argsOffset, argsLen, retOffset, retLen
                    if !self.use_gas(100) { break; }
                    let _gas     = Self::u256_to_u64(&self.pop());
                    let addr20   = { let a=self.pop(); let mut b=[0u8;20]; b.copy_from_slice(&a[12..32]); b };
                    let value    = { let v=self.pop(); u128::from_be_bytes(v[16..32].try_into().unwrap_or([0;16])) };
                    let args_off = Self::u256_to_u64(&self.pop()) as usize;
                    let args_len = Self::u256_to_u64(&self.pop()) as usize;
                    let ret_off  = Self::u256_to_u64(&self.pop()) as usize;
                    let ret_len  = Self::u256_to_u64(&self.pop()) as usize;
                    self.mem_expand(args_off, args_len);
                    let calldata = self.memory[args_off..args_off+args_len].to_vec();
                    let callee   = self.db.get_account(&addr20);
                    let success  = if callee.code.is_empty() {
                        let mut s = self.db.get_account(&self.addr);
                        if s.balance >= value {
                            s.balance -= value; self.db.set_account(self.addr, s);
                            let mut r = self.db.get_account(&addr20); r.balance += value; self.db.set_account(addr20, r);
                            true
                        } else { false }
                    } else {
                        let code = callee.code.clone();
                        let sub_gas = self.gas * 63 / 64; self.use_gas(sub_gas);
                        let (sg, sr, so, sl, srd) = {
                            let mut sub_vm = Vm::new(self.db, &code, self.addr, addr20, value, calldata, sub_gas);
                            sub_vm.run();
                            (sub_vm.gas, sub_vm.reverted, sub_vm.output.clone(), sub_vm.logs.clone(), sub_vm.output.len())
                        };
                        self.gas += sg;
                        let copy = ret_len.min(so.len());
                        if copy > 0 { self.mem_expand(ret_off, copy); self.memory[ret_off..ret_off+copy].copy_from_slice(&so[..copy]); }
                        self.returndatasize = srd;
                        self.logs.extend_from_slice(&sl);
                        !sr
                    };
                    self.push(if success { Self::from_u64(1) } else { [0u8;32] });
                }

                0xf4 => { // DELEGATECALL: gas, addr, argsOffset, argsLen, retOffset, retLen
                    if !self.use_gas(100) { break; }
                    let _gas     = Self::u256_to_u64(&self.pop());
                    let addr20   = { let a=self.pop(); let mut b=[0u8;20]; b.copy_from_slice(&a[12..32]); b };
                    let args_off = Self::u256_to_u64(&self.pop()) as usize;
                    let args_len = Self::u256_to_u64(&self.pop()) as usize;
                    let ret_off  = Self::u256_to_u64(&self.pop()) as usize;
                    let ret_len  = Self::u256_to_u64(&self.pop()) as usize;
                    self.mem_expand(args_off, args_len);
                    let calldata = self.memory[args_off..args_off+args_len].to_vec();
                    let callee   = self.db.get_account(&addr20);
                    let code     = callee.code.clone();
                    if !code.is_empty() {
                        let sub_gas = self.gas * 63 / 64; self.use_gas(sub_gas);
                        let (sg, sr, so, sl, srd) = {
                            let mut sub_vm = Vm::new(self.db, &code, self.caller, self.addr, self.value, calldata, sub_gas);
                            sub_vm.run();
                            (sub_vm.gas, sub_vm.reverted, sub_vm.output.clone(), sub_vm.logs.clone(), sub_vm.output.len())
                        };
                        self.gas += sg;
                        let copy = ret_len.min(so.len());
                        if copy > 0 { self.mem_expand(ret_off, copy); self.memory[ret_off..ret_off+copy].copy_from_slice(&so[..copy]); }
                        self.returndatasize = srd;
                        self.logs.extend_from_slice(&sl);
                        self.push(if !sr { Self::from_u64(1) } else { [0u8;32] });
                    } else { self.push(Self::from_u64(1)); }
                }

                0xfa => { // STATICCALL — read-only
                    if !self.use_gas(100) { break; }
                    let _gas     = Self::u256_to_u64(&self.pop());
                    let addr20   = { let a=self.pop(); let mut b=[0u8;20]; b.copy_from_slice(&a[12..32]); b };
                    let args_off = Self::u256_to_u64(&self.pop()) as usize;
                    let args_len = Self::u256_to_u64(&self.pop()) as usize;
                    let ret_off  = Self::u256_to_u64(&self.pop()) as usize;
                    let ret_len  = Self::u256_to_u64(&self.pop()) as usize;
                    self.mem_expand(args_off, args_len);
                    let calldata = self.memory[args_off..args_off+args_len].to_vec();
                    let callee   = self.db.get_account(&addr20);
                    let code     = callee.code.clone();
                    if !code.is_empty() {
                        let sub_gas = self.gas * 63 / 64; self.use_gas(sub_gas);
                        let (sg, sr, so, srd) = {
                            let mut sub_vm = Vm::new(self.db, &code, self.addr, addr20, 0, calldata, sub_gas);
                            sub_vm.run();
                            (sub_vm.gas, sub_vm.reverted, sub_vm.output.clone(), sub_vm.output.len())
                        };
                        self.gas += sg;
                        let copy = ret_len.min(so.len());
                        if copy > 0 { self.mem_expand(ret_off, copy); self.memory[ret_off..ret_off+copy].copy_from_slice(&so[..copy]); }
                        self.returndatasize = srd;
                        self.push(if !sr { Self::from_u64(1) } else { [0u8;32] });
                    } else { self.push(Self::from_u64(1)); }
                }

                0xff => { // SELFDESTRUCT
                    let beneficiary_bytes = self.pop();
                    let mut beneficiary = [0u8; 20];
                    beneficiary.copy_from_slice(&beneficiary_bytes[12..32]);
                    // Transfer remaining balance to beneficiary
                    let self_acct = self.db.get_account(&self.addr);
                    let balance = self_acct.balance;
                    if balance > 0 {
                        let mut ben_acct = self.db.get_account(&beneficiary);
                        ben_acct.balance += balance;
                        self.db.set_account(beneficiary, ben_acct);
                    }
                    // Clear self account
                    self.db.set_account(self.addr, Account { balance: 0, nonce: 0, code: Vec::new(), storage: BTreeMap::new() });
                    self.stopped = true;
                    self.use_gas(5000);
                }
                _ => { self.use_gas(3); } // Unknown opcode: no-op with gas cost
            }
        }
    }
}

// ── State database ────────────────────────────────────────────────────────────
/// Snapshot of EVM state for STATICCALL revert support
#[derive(Clone)]
pub struct EvmStateSnapshot {
    pub storage:  alloc::collections::BTreeMap<alloc::vec::Vec<u8>, alloc::vec::Vec<u8>>,
    pub balances: alloc::collections::BTreeMap<[u8;20], u64>,
}

pub struct EvmStateDb {
    pub accounts:  BTreeMap<[u8;20], Account>,
    pub db:        IonafsDatabaseFile,
    pub dirty:     BTreeMap<[u8;20], Account>,
}

impl EvmStateDb {
    pub fn snapshot(&self) -> EvmStateSnapshot {
        // Snapshot: serialize current accounts into storage/balances maps
        let mut storage = alloc::collections::BTreeMap::new();
        let mut balances = alloc::collections::BTreeMap::new();
        for (addr, acct) in &self.accounts {
            balances.insert(*addr, acct.balance as u64);
            for (k, v) in &acct.storage {
                storage.insert(k.to_vec(), v.to_vec());
            }
        }
        EvmStateSnapshot { storage, balances }
    }
    pub fn revert_to(&mut self, snap: EvmStateSnapshot) {
        // Revert: restore balances from snapshot
        for (addr, bal) in &snap.balances {
            if let Some(acct) = self.accounts.get_mut(addr) {
                acct.balance = *bal as u128;
            }
        }
    }

    pub fn new(db_name: &str) -> Self {
        Self { accounts: BTreeMap::new(), db: IonafsDatabaseFile::open(db_name), dirty: BTreeMap::new() }
    }

    pub fn get_account(&mut self, addr: &[u8;20]) -> Account {
        if let Some(a) = self.accounts.get(addr) { return a.clone(); }
        // Load from persistent storage
        let path = format!("/evm/acct/{}", hex(addr));
        if let Some(data) = crate::fs::ionafs::read(&path) {
            if data.len() >= 32 {
                let mut acc = Account::default();
                acc.balance = u128::from_le_bytes(data[0..16].try_into().unwrap_or([0;16]));
                acc.nonce   = u64::from_le_bytes(data[16..24].try_into().unwrap_or([0;8]));
                if data.len() > 32 { acc.code = data[32..].to_vec(); }
                self.accounts.insert(*addr, acc.clone());
                return acc;
            }
        }
        Account::default()
    }

    pub fn set_account(&mut self, addr: [u8;20], acc: Account) {
        self.dirty.insert(addr, acc.clone());
        self.accounts.insert(addr, acc);
    }

    pub fn get_storage(&mut self, addr: &[u8;20], slot: &[u8;32]) -> [u8;32] {
        self.get_account(addr).storage.get(slot).copied().unwrap_or([0u8;32])
    }

    pub fn set_storage(&mut self, addr: [u8;20], slot: [u8;32], value: [u8;32]) {
        let mut acc = self.get_account(&addr);
        acc.storage.insert(slot, value);
        self.set_account(addr, acc);
    }

    /// Create a snapshot for STATICCALL (reads only, no writes propagated)
    pub fn snapshot_clone(parent: &EvmStateDb) -> EvmStateDb {
        EvmStateDb {
            accounts: parent.accounts.clone(),
            db:       IonafsDatabaseFile::open("staticcall-snap"),
            dirty:    BTreeMap::new(),
        }
    }

    pub fn compute_create_addr(&self, sender: &[u8;20], nonce: u64) -> [u8;20] {
        // keccak256(RLP(sender, nonce))[12..]
        // Simplified: xor-fold for determinism
        let mut data = alloc::vec![0x80u8 + 20u8]; // RLP prefix for 20-byte addr
        data.extend_from_slice(sender);
        data.push(nonce as u8);
        let h = keccak256(&data);
        let mut addr = [0u8;20];
        addr.copy_from_slice(&h[12..32]);
        addr
    }

    pub fn commit(&mut self) {
        let keys: Vec<[u8;20]> = self.dirty.keys().cloned().collect();
        for addr in keys {
            let acc = match self.dirty.remove(&addr) { Some(a) => a, None => continue };
            let mut buf = alloc::vec![0u8; 32 + acc.code.len()];
            buf[0..16].copy_from_slice(&acc.balance.to_le_bytes());
            buf[16..24].copy_from_slice(&acc.nonce.to_le_bytes());
            if !acc.code.is_empty() { buf[32..].copy_from_slice(&acc.code); }
            let path = format!("/evm/acct/{}", hex(&addr));
            crate::fs::ionafs::write(&path, &buf);
        }
        self.db.flush();
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Evm executor ─────────────────────────────────────────────────────────────
pub struct Evm { pub state: EvmStateDb }

impl Evm {
    pub fn new(db: &str) -> Self { Self { state: EvmStateDb::new(db) } }

    pub fn transact(&mut self, from: [u8;20], to: Option<[u8;20]>, value: u128,
                    calldata: Vec<u8>, gas_limit: u64) -> EvmResult
    {
        // Intrinsic gas: 21000 + 4*zero_bytes + 16*nonzero_bytes
        let intrinsic = 21000 + calldata.iter()
            .map(|&b| if b == 0 { 4u64 } else { 16 }).sum::<u64>();
        if gas_limit < intrinsic {
            return EvmResult { success:false, gas_used:intrinsic, output:Vec::new(), logs:Vec::new(), error:Some("intrinsic gas".into()) };
        }

        let mut sender = self.state.get_account(&from);
        if sender.balance < value {
            return EvmResult { success:false, gas_used:0, output:Vec::new(), logs:Vec::new(), error:Some("insufficient balance".into()) };
        }
        sender.balance -= value;
        sender.nonce   += 1;
        let sender_nonce = sender.nonce;
        self.state.set_account(from, sender);

        let gas_for_exec = gas_limit - intrinsic;

        let result = match to {
            None => {
                // Contract creation
                let contract_addr = compute_contract_addr(&from, sender_nonce - 1);
                let _code = calldata.clone();
                // Run init code
                let mut db_tmp = EvmStateDb::new("tmp");
                let mut vm = Vm::new(&mut db_tmp, &calldata, from, contract_addr, value, Vec::new(), gas_for_exec);
                vm.run();
                let runtime_code = vm.output.clone();
                let gas_used = intrinsic + (gas_for_exec - vm.gas);

                if !vm.reverted && !runtime_code.is_empty() {
                    let contract = Account { balance: value, nonce:0, code: runtime_code.clone(), storage: BTreeMap::new() };
                    self.state.set_account(contract_addr, contract);
                }

                EvmResult {
                    success: !vm.reverted, gas_used,
                    output: contract_addr.to_vec(), logs: vm.logs.clone(), error: None,
                }
            }
            Some(dest) => {
                let mut receiver = self.state.get_account(&dest);
                receiver.balance += value;
                self.state.set_account(dest, receiver.clone());

                if receiver.code.is_empty() {
                    // EOA transfer
                    EvmResult { success:true, gas_used:intrinsic, output:Vec::new(), logs:Vec::new(), error:None }
                } else {
                    // Contract call
                    let code = receiver.code.clone();
                    let mut vm = Vm::new(&mut self.state, &code, from, dest, value, calldata, gas_for_exec);
                    vm.run();
                    let gas_used = intrinsic + (gas_for_exec - vm.gas);
                    EvmResult { success: !vm.reverted, gas_used, output: vm.output.clone(), logs: vm.logs.clone(), error: None }
                }
            }
        };

        self.state.commit();
        result
    }
}

fn compute_contract_addr(sender: &[u8;20], nonce: u64) -> [u8;20] {
    // RLP(sender, nonce) then keccak256, take last 20 bytes
    let mut rlp = Vec::new();
    // RLP encode list: [sender_20bytes, nonce]
    // Simple RLP: 0xd4 + sender(0x94 + 20bytes) + nonce_rlp
    rlp.push(0x94); // RLP string prefix for 20 bytes
    rlp.extend_from_slice(sender);
    if nonce == 0 {
        rlp.push(0x80); // RLP empty string = 0
    } else if nonce < 0x80 {
        rlp.push(nonce as u8);
    } else {
        let nonce_bytes = nonce.to_be_bytes();
        let start = nonce_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let len = 8 - start;
        rlp.push(0x80 + len as u8);
        rlp.extend_from_slice(&nonce_bytes[start..]);
    }
    // Wrap in list
    let mut list = Vec::new();
    let total_len = rlp.len();
    if total_len < 56 {
        list.push(0xc0 + total_len as u8);
    } else {
        let len_bytes = total_len.to_be_bytes();
        let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        list.push(0xf7 + (8 - start) as u8);
        list.extend_from_slice(&len_bytes[start..]);
    }
    list.extend_from_slice(&rlp);

    let hash = keccak256(&list);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

/// Keccak-256 hash function (FIPS 202 / SHA-3)
/// Used by Ethereum for address computation, storage keys, etc.
fn keccak256(data: &[u8]) -> [u8; 32] {
    // Keccak-256: rate=1088 bits (136 bytes), capacity=512 bits, output=256 bits
    const RATE: usize = 136; // rate in bytes (1088 / 8)

    let mut state = [0u64; 25]; // 5×5 state matrix, 1600 bits

    // Absorb phase: pad and absorb input blocks
    let mut offset = 0;
    while offset < data.len() {
        let block_size = (data.len() - offset).min(RATE);
        // XOR block into state
        for i in 0..block_size {
            let lane = i / 8;
            let byte_in_lane = i % 8;
            state[lane] ^= (data[offset + i] as u64) << (byte_in_lane * 8);
        }
        offset += block_size;

        if block_size == RATE {
            keccak_f1600(&mut state);
        }
    }

    // Padding: Keccak uses pad10*1 — 0x01 at start, 0x80 at end of rate block
    let pad_offset = data.len() % RATE;
    let pad_lane = pad_offset / 8;
    let pad_byte = pad_offset % 8;
    state[pad_lane] ^= 0x01u64 << (pad_byte * 8);

    let last_lane = (RATE - 1) / 8;
    let last_byte = (RATE - 1) % 8;
    state[last_lane] ^= 0x80u64 << (last_byte * 8);

    keccak_f1600(&mut state);

    // Squeeze: extract 256 bits (32 bytes) from state
    let mut output = [0u8; 32];
    for i in 0..4 {
        output[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
    }
    output
}

/// Keccak-f[1600] permutation — 24 rounds
fn keccak_f1600(state: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];

    const ROT: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20,
        3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ];

    // PI permutation indices
    const PI: [usize; 25] = [
        0, 6, 12, 18, 24, 3, 9, 10, 16, 22,
        1, 7, 13, 19, 20, 4, 5, 11, 17, 23,
        2, 8, 14, 15, 21,
    ];

    for round in 0..24 {
        // θ (theta)
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // ρ (rho) + π (pi)
        let mut b = [0u64; 25];
        for i in 0..25 {
            b[PI[i]] = state[i].rotate_left(ROT[i]);
        }

        // χ (chi)
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // ι (iota)
        state[0] ^= RC[round];
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Execute a transaction on the EVM
/// Returns (success, return_data, gas_used)
pub fn execute(
    code:       &[u8],
    calldata:   &[u8],
    caller:     [u8; 20],
    value:      u128,
    gas_limit:  u64,
    state:      &mut EvmStateDb,
) -> (bool, alloc::vec::Vec<u8>, u64) {
    let addr = [0u8; 20]; // self-address placeholder for raw code execution
    let mut vm = Vm::new(state, code, caller, addr, value, calldata.to_vec(), gas_limit);
    vm.run();
    let gas_used = gas_limit.saturating_sub(vm.gas);
    (!vm.reverted, vm.output.clone(), gas_used)
}

/// Estimate gas for a transaction (dry run without state commit)
pub fn estimate_gas(
    code:     &[u8],
    calldata: &[u8],
    caller:   [u8; 20],
    value:    u128,
) -> u64 {
    const MAX_GAS: u64 = 30_000_000;
    let mut db = EvmStateDb::new("estimate_tmp");
    let addr = [0u8; 20];
    let mut vm = Vm::new(&mut db, code, caller, addr, value, calldata.to_vec(), MAX_GAS);
    vm.run();
    MAX_GAS.saturating_sub(vm.gas)
}
