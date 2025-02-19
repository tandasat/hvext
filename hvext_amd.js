"use strict";

// Registers commands.
function initializeScript() {
    return [
        new host.apiVersionSupport(1, 7),
        new host.functionAlias(hvextHelp, "hvext_help"),
        new host.functionAlias(dumpIo, "dump_io"),
        new host.functionAlias(dumpMsr, "dump_msr"),
        new host.functionAlias(dumpNpt, "dump_npt"),
        new host.functionAlias(dumpVmcb, "dump_vmcb"),
        new host.functionAlias(indexesFor, "indexes"),
        new host.functionAlias(pte, "pte"),
    ];
}

// Initializes the extension.
function invokeScript() {
    exec(".load kext");
    let hvImageRange = findHvImageRange();
    let addrs = findVmrunAddresses(hvImageRange);
    for (let i = 0; i < addrs.length; ++i) {
        let offset = addrs[i] - hvImageRange.start;
        println(`bp hv+${hex(offset)} ".echo Breakpoint ${i} hit; r rax"`);
    }

    println("\nTo find the address of a VMCB, break on VMRUN using the above bp commands.");
    println("hvext loaded. Execute !hvext_help [command] for the help message.");

    // Returns the range of the virtual address where the HV image is mapped.
    function findHvImageRange() {
        // Get the range with "lm".
        // eg: fffff876`b89e0000 fffff876`b8de2000   hv         (no symbols)
        let chunks = exec("lm m hv").Last().split(" ");
        let start = chunks[0].replace("`", "");
        let end = chunks[1].replace("`", "");
        return {
            "start": BigInt("0x" + start),
            "end": BigInt("0x" + end),
        };
    }

    // Finds the addresses with a sequence of VMLOAD and VMRUN instructions.
    function findVmrunAddresses(hvImageRange) {
        const isVmloadVmrun = (memory, i) => (
            memory[i + 0] == 0x0f &&    // VMLOAD
            memory[i + 1] == 0x01 &&
            memory[i + 2] == 0xda &&
            memory[i + 3] == 0x0f &&    // VMRUN
            memory[i + 4] == 0x01 &&
            memory[i + 5] == 0xd8
        );

        // Search each page in the HV image range.
        let addresses = [];
        for (let pageBase = hvImageRange.start; pageBase != hvImageRange.end; pageBase += 0x1000n) {
            if (pageBase % 0x10000n == 0n) {
                print(".");
            }
            addresses = addresses.concat(searchMemory(pageBase, 0x1000, isVmloadVmrun));
        }
        println("");
        assert(addresses.length > 0, "No VMRUN instruction found");
        return addresses;

        // Finds an array of virtual addresses that matches the specified condition.
        function searchMemory(address, size, predicate) {
            // Memory read can fail if the address is not mapped.
            try {
                var memory = host.memory.readMemoryValues(toInt64(address), size);
            } catch (error) {
                return [];
            }

            let addresses = [];
            for (let i = 0; i < size; i++) {
                if (predicate(memory, i)) {
                    addresses.push(address + BigInt(i));
                }
            }
            return addresses;
        }
    }
}

// Implements the !hvext_help command.
function hvextHelp(command) {
    switch (command) {
        case "dump_io":
            println("dump_io <pa> [,verbosity] - Displays contents of the IO permissions map.");
            println("   pa - The physical address of the IO permissions map to dump.");
            println("   verbosity - 0 = Shows only IO ports that are readable or writable from the guest (default).");
            println("               1 = Shows protections of all ports managed by the IO permissions map.");
            break;
        case "dump_msr":
            println("dump_msr <pa> [,verbosity] - Displays contents of the MSR permissions map.");
            println("   pa - The physical address of the MSR permissions map to dump.");
            println("   verbosity - 0 = Shows only MSRs that are readable or writable from the guest (default).");
            println("               1 = Shows protections of all MSRs managed by the MSR permissions map.");
            break;
        case "dump_npt":
            println("dump_npt <ncr3> [,verbosity] - Displays guest physical address translation managed through NPT.");
            println("   ncr3 - The N_CR3 value to dump its translation.");
            println("   verbosity - 0 = Shows valid translations in a summarized format (default).");
            println("               1 = Shows both valid and invalid translations in a summarized format.");
            println("               2 = Shows every valid translations without summarizing it.");
            break;
        case "dump_vmcb":
            println("dump_vmcb <pa> [,verbosity] - Displays contents of the VMCB.");
            println("   pa - The physical address of VMCB to dump.");
            println("   verbosity - 0 = Shows only VMCB (default).");
            println("               1 = Shows more details of some field values.");
            break;
        case "indexes":
            println("indexes [address] - Displays index values to walk paging structures for the given address.");
            println("   address - The address to decode (default= 0).");
            break;
        case "pte":
            println("pte [address [,pml4]] - Displays contents of paging structure entries used to translated the given address.");
            println("   address - The address to translate with the paging structures (default= 0).");
            println("   pml4 - The address of PML4, or the N_CR3 value (default= current CR3).");
            break;
        case undefined:
        default:
            println("hvext_help [command] - Displays this message.");
            println("dump_io <pa> [,verbosity] - Displays contents of the IO permissions map.");
            println("dump_msr <pa> [,verbosity] - Displays contents of the MSR permissions map.");
            println("dump_npt <ncr3> [,verbosity] - Displays guest physical address translation managed through NPT.");
            println("dump_vmcb <pa> [,verbosity] - Displays contents of the VMCB.");
            println("indexes [address] - Displays index values to walk paging structures for the given address.");
            println("pte [address [,pml4]] - Displays contents of paging structure entries used to translated the given address.");
            break;
    }
}

// Implements the !dump_io command.
function dumpIo(iopmPa_, verbosity = 0) {
    let iopmPa = BigInt(iopmPa_);
    if (iopmPa != (iopmPa & ~0xfffn)) {
        println("IO permissions map must be at 4KB aligned address");
        return;
    }

    new Iopm(iopmPa).dump(verbosity);
}

// Implements the !dump_msr command.
function dumpMsr(msrpmPa_, verbosity = 0) {
    let msrpmPa = BigInt(msrpmPa_);
    if (msrpmPa != (msrpmPa & ~0xfffn)) {
        println("MSR permissions map must be at 4KB aligned address");
        return;
    }

    new Msrpm(msrpmPa).dump(verbosity);
}

// Implements the !dump_npt command.
function dumpNpt(ncr3_, verbosity = 0) {
    let ncr3 = BigInt(ncr3_);
    if (ncr3 != (ncr3 & ~0xfffn)) {
        println("NCR3 must be at 4KB aligned address");
        return;
    }

    new NestedPageTables(ncr3).dump(verbosity);
}

// Implements the !dump_vmcb command.
function dumpVmcb(vmcbPa_, verbosity = 0) {
    let vmcbPa = BigInt(vmcbPa_);
    if (vmcbPa != (vmcbPa & ~0xfffn)) {
        println("VMCB must be at 4KB aligned address");
        return;
    }

    new Vmcb(vmcbPa).dump(verbosity);
}

// Implements the !indexes command.
function indexesFor(address) {
    if (address === undefined) {
        address = 0;
    }
    return {
        "pt": Number(bits(address, 12, 9)),
        "pd": Number(bits(address, 21, 9)),
        "pdpt": Number(bits(address, 30, 9)),
        "pml4": Number(bits(address, 39, 9)),
    };
}

// Implements the !pte command.
function pte(la_, pml4_) {
    if (la_ === undefined) {
        la_ = 0;
    }
    if (pml4_ === undefined) {
        pml4_ = host.currentThread.Registers.Kernel.cr3.bitwiseAnd(~0xfff);
    }
    let la = BigInt(la_);
    let pml4 = BigInt(pml4_);

    let indexFor = indexesFor(la);
    let i1 = BigInt(indexFor.pt);
    let i2 = BigInt(indexFor.pd);
    let i3 = BigInt(indexFor.pdpt);
    let i4 = BigInt(indexFor.pml4);

    // Pick and check PML4e.
    let pml4e = new PsEntry(readEntry(pml4 + 8n * i4));
    if (!pml4e.flags.present()) {
        println("PML4e at " + hex(pml4 + 8n * i4));
        println("contains " + hex(pml4e.value));
        println("pfn " + pml4e);
        return;
    }
    let allNonLeafWritable = pml4e.flags.write;

    // Pick and check PDPTe.
    let pdpt = pml4e.pfn << 12n;
    let pdpte = new PsEntry(readEntry(pdpt + 8n * i3), allNonLeafWritable);
    if (!pdpte.flags.present() || pdpte.flags.large) {
        println(
            "PML4e at " + hex(pml4 + 8n * i4).padEnd(19) +
            "PDPTe at " + hex(pdpt + 8n * i3));
        println(
            "contains " + hex(pml4e.value).padEnd(19) +
            "contains " + hex(pdpte.value));
        println(
            "pfn " + (pml4e + "").padEnd(24) +
            "pfn " + pdpte);
        return;
    }
    allNonLeafWritable &= pdpte.flags.write;

    // Pick and check PDe.
    let pd = pdpte.pfn << 12n;
    let pde = new PsEntry(readEntry(pd + 8n * i2), allNonLeafWritable);
    if (!pde.flags.present() || pde.flags.large) {
        println(
            "PML4e at " + hex(pml4 + 8n * i4).padEnd(19) +
            "PDPTe at " + hex(pdpt + 8n * i3).padEnd(19) +
            "PDe at " + hex(pd + 8n * i2));
        println(
            "contains " + hex(pml4e.value).padEnd(19) +
            "contains " + hex(pdpte.value).padEnd(19) +
            "contains " + hex(pde.value));
        println(
            "pfn " + (pml4e + "").padEnd(24) +
            "pfn " + (pdpte + "").padEnd(24) +
            "pfn " + pde);
        return;
    }
    allNonLeafWritable &= pde.flags.write;

    // Pick PTe.
    let pt = pde.pfn << 12n;
    let pte = new PsEntry(readEntry(pt + 8n * i1), allNonLeafWritable);
    println(
        "PML4e at " + hex(pml4 + 8n * i4).padEnd(19) +
        "PDPTe at " + hex(pdpt + 8n * i3).padEnd(19) +
        "PDe at " + hex(pd + 8n * i2).padEnd(21) +
        "PTe at " + hex(pt + 8n * i1));
    println(
        "contains " + hex(pml4e.value).padEnd(19) +
        "contains " + hex(pdpte.value).padEnd(19) +
        "contains " + hex(pde.value).padEnd(19) +
        "contains " + hex(pte.value));
    println(
        "pfn " + (pml4e + "").padEnd(24) +
        "pfn " + (pdpte + "").padEnd(24) +
        "pfn " + (pde + "").padEnd(24) +
        "pfn " + pte);

    // Reads a 64bit value at the specified physical address.
    function readEntry(address) {
        let line = exec(`!dq ${hex(address)} l1`).Last();
        return BigInt("0x" + line.replace(/`/g, "").substring(10).trim().split(" "));
    }
}

class Vmcb {
    constructor(address) {
        assert(address == (address & ~0xfffn), "VMCB must be at 4KB aligned address");

        let bytes = readPhysical(address, 0x1000);
        let fields = {};
        for (let [key, value] of Object.entries(VMCB_LAYOUT)) {
            let offset = Number(key);
            let type = value[0];
            let description = value[1];
            let data = (type.size > 8) ?
                bytes.slice(offset, offset + type.size) :
                toNumber(bytes.slice(offset, offset + type.size));
            let field = new type(description, data);
            fields[offset] = field;
        }
        this.address = address;
        this.fields = fields;

        // Converts an array of bytes (integers) into BigInt.
        function toNumber(bytes) {
            assert(bytes.length == 1 || bytes.length == 2 || bytes.length == 4 || bytes.length == 8,
                "The array must be either 1, 2, 4, or 8 bytes");

            let result = 0n;
            for (let i = 0n; i < bytes.length; i++) {
                result |= BigInt(bytes[i]) << (i * 8n);
            }
            return result;
        }
    }

    dump(verbosity) {
        println(`VMCB @ ${hex(this.address)}`);
        for (let [key, field] of Object.entries(this.fields)) {
            let offset = Number(key);
            println(`+${hex(offset, 3)}: ${field}`);
        }
        if (verbosity != 0) {
            if (bits(this.fields[0x00c].value, 27, 1)) {
                this.fields[0x040].iopm.dump(0);
            } else {
                println("IO permissions map is not enabled. IO port access does not cause VM-exit.");
            }

            if (bits(this.fields[0x00c].value, 28, 1)) {
                this.fields[0x048].msrpm.dump(0);
            } else {
                println("MSR permissions map is not enabled. MSR access does not cause VM-exit.");
            }

            if (bits(this.fields[0x090].value, 0, 1)) {
                this.fields[0x0b0].npt.dump(0);
            } else {
                println("Nested paging is not enabled.");
            }
        }
    }
}

class GenericU8 {
    static size = 1;

    constructor(description, value) {
        assertOnValue(value, GenericU8.size);
        this.description = description;
        this.value = value;
    }

    toString() {
        return hex(this.value) + " -- " + this.description;
    }
}

class GenericU16 {
    static size = 2;

    constructor(description, value) {
        assertOnValue(value, GenericU16.size);
        this.description = description;
        this.value = value;
    }

    toString() {
        return hex(this.value) + " -- " + this.description;
    }
}

class GenericU32 {
    static size = 4;

    constructor(description, value) {
        assertOnValue(value, GenericU32.size);
        this.description = description;
        this.value = value;
    }

    toString() {
        return hex(this.value) + " -- " + this.description;
    }
}

class GenericU64 {
    static size = 8;

    constructor(description, value) {
        assertOnValue(value, GenericU64.size);
        this.description = description;
        this.value = value;
    }

    toString() {
        return hex(this.value) + " -- " + this.description;
    }
}

class Array15U8 {
    static size = 15;

    constructor(description, value) {
        assert(value.length == Array15U8.size, "Value length mismatch");
        this.description = description;
        this.value = value;
    }

    toString() {
        return this.value.map(num => `0x${num.toString(16).padStart(2, "0")}`) + " -- " + this.description;
    }
}

class Array32U8 {
    static size = 32;

    constructor(description, value) {
        assert(value.length == Array32U8.size, "Value length mismatch");
        this.description = description;
        this.value = value;
    }

    toString() {
        return this.value.map(num => `0x${num.toString(16).padStart(2, "0")}`) + " -- " + this.description;
    }
}

class Array256U8 {
    static size = 256;

    constructor(description, value) {
        assert(value.length == Array256U8.size, "Value length mismatch");
        this.description = description;
        this.value = value;
    }

    toString() {
        return this.value.map(num => `0x${num.toString(16).padStart(2, "0")}`) + " -- " + this.description;
    }
}

class MsrpmBasePa {
    static size = 8;

    constructor(description, value) {
        assertOnValue(value, MsrpmBasePa.size);
        this.description = description;
        this.value = value;
        this.msrpm = new Msrpm(value);
    }

    toString() {
        return hex(this.value) + " -- " + this.description;
    }
}

// See: 15.11 MSR Intercepts
class Msrpm {
    constructor(address) {
        class MsrEntry {
            constructor(bitPos, readProtected, writeProtected) {
                if (bitPos < 0x4000) {
                    this.number = bitPos / 2;
                } else if (bitPos < 0x8000) {
                    this.number = (bitPos - 0x4000) / 2 + 0xc0000000;
                } else if (bitPos < 0xc000) {
                    this.number = (bitPos - 0x8000) / 2 + 0xc0010000;
                } else {
                    assert(false, "A reserved bit is set");
                }
                this.readProtected = readProtected;
                this.writeProtected = writeProtected;
            }

            toString() {
                return (
                    (this.readProtected ? "-" : "R") +
                    (this.writeProtected ? "-" : "W") +
                    " " + hex(this.number)
                );
            }
        }

        assert(address == (address & ~0xfffn), "MSR permissions map must be at 4KB aligned address");

        // Parse only up to 0x1800 because the rest are reserved.
        let msrs = [];
        let bytes = readPhysical(address, 0x2000);
        for (let i = 0; i < 0x1800; i++) {
            let byte = bytes[i];
            for (let bitPos = 0; bitPos < 8; bitPos += 2) {
                let readProtected = Boolean(bits(byte, bitPos, 1));
                let writeProtected = Boolean(bits(byte, bitPos + 1, 1));
                msrs.push(new MsrEntry(i * 8 + bitPos, readProtected, writeProtected));
            }
        }
        this.address = address;
        this.msrs = msrs;
    }

    dump(verbosity) {
        class MsrAccessibilityRange {
            constructor(begin, end) {
                this.begin = begin;
                this.end = end;
            }

            toString() {
                return (this.begin.readProtected ? "-" : "R") +
                    (this.begin.writeProtected ? "-" : "W") +
                    ((this.begin == this.end) ?
                        `  ${hex(this.begin.number)}` :
                        ` [${hex(this.begin.number)}, ${hex(this.end.number)}]`);
            }
        }

        let begin = undefined;
        let end = undefined;
        let ranges = [];
        for (let msr of this.msrs) {
            if (begin === undefined) {
                begin = end = msr;
            } else if (end.number == msr.number - 1 &&
                end.readProtected == msr.readProtected &&
                end.writeProtected == msr.writeProtected) {
                // Contiguous MSR with the same permissions. Extend the range.
                end = msr;
            } else {
                // Non-contiguous MSR or different permissions. Save the range and start a new one.
                ranges.push(new MsrAccessibilityRange(begin, end));
                begin = end = msr;
            }
        }
        ranges.push(new MsrAccessibilityRange(begin, end));

        println(`MSRPM @ ${hex(this.address)}`);
        if (verbosity == 0) {
            ranges.filter(range => !range.begin.readProtected || !range.begin.writeProtected).map(println);
        } else {
            ranges.map(println);
        }
    }
}

class IopmBasePa {
    static size = 8;

    constructor(description, value) {
        assertOnValue(value, IopmBasePa.size);
        this.description = description;
        this.value = value;
        this.iopm = new Iopm(value);
    }

    toString() {
        return hex(this.value) + " -- " + this.description;
    }
}

// See: 15.10.1 I/O Permissions Map
class Iopm {
    constructor(address) {
        class IoPortEntry {
            constructor(port, rwProtected) {
                this.number = port;
                this.rwProtected = rwProtected;
            }

            toString() {
                return (this.rwProtected ? "--" : "RW") + " " + hex(this.number);
            }
        }

        assert(address == (address & ~0xfffn), "IO permissions map must be at 4KB aligned address");

        // Parse only up to 0x2000 because the last 4KB of the IO permissions
        // bitmap is used only for its first 3 bits, corresponding to IO at
        // 0xffff with 32bit-width.
        let ports = [];
        let bytes = readPhysical(address, 0x3000);
        for (let i = 0; i < 0x2000; i++) {
            let byte = bytes[i];
            for (let bitPos = 0; bitPos < 8; bitPos++) {
                let rwProtected = Boolean(bits(byte, bitPos, 1));
                ports.push(new IoPortEntry(i * 8 + bitPos, rwProtected));
            }
        }
        this.address = address;
        this.ports = ports;
    }

    dump(verbosity) {
        class IoAccessibilityRange {
            constructor(begin, end) {
                this.begin = begin;
                this.end = end;
            }

            toString() {
                return (this.begin.rwProtected ? "-- " : "RW ") +
                    ((this.begin == this.end) ?
                        ` ${hex(this.begin.number)}` :
                        `[${hex(this.begin.number)}, ${hex(this.end.number)}]`);
            }
        }

        let begin = undefined;
        let end = undefined;
        let ranges = [];
        for (let port of this.ports) {
            if (begin === undefined) {
                begin = end = port;
            } else if (end.number == port.number - 1 &&
                end.rwProtected == port.rwProtected) {
                // Contiguous IO with the same permissions. Extend the range.
                end = port;
            } else {
                // Non-contiguous IO or different permissions. Save the range and start a new one.
                ranges.push(new IoAccessibilityRange(begin, end));
                begin = end = port;
            }
        }
        ranges.push(new IoAccessibilityRange(begin, end));

        println(`IOPM @ ${hex(this.address)}`);
        if (verbosity == 0) {
            ranges.filter(range => !range.begin.rwProtected).map(println);
        } else {
            ranges.map(println);
        }
    }
}

class Ncr3 {
    static size = 8;

    constructor(description, value) {
        assertOnValue(value, Ncr3.size);
        this.description = description;
        this.value = value;
        this.npt = new NestedPageTables(value);
    }

    toString() {
        return hex(this.value) + " -- " + this.description;
    }
}

class NestedPageTables {
    constructor(ncr3) {
        class Region {
            constructor(gpa, pa, flags, size) {
                this.gpa = gpa;
                this.pa = pa;
                this.flags = flags;
                this.size = size;
                this.identityMapping = (gpa == pa);
            }

            toString() {
                let begin = hex(this.gpa).padStart(12);
                let end = hex(this.gpa + this.size).padStart(12);
                let translation = (this.identityMapping) ?
                    "Identity".padEnd(12) :
                    hex(this.pa).padStart(12);
                return `${begin} - ${end} -> ${translation} ${this.flags}`;
            }
        }

        const SIZE_4KB = 0x1000;
        const SIZE_2MB = 0x20_0000;
        const SIZE_1GB = 0x4000_0000;
        const SIZE_512GB = 0x80_0000_0000;

        // Walk through all NPT entries and accumulate them as regions.
        let pml4 = new Pml4(ncr3);
        let regions = [];
        for (let gpa = 0, pageSize = 0; ; gpa += pageSize) {
            let indexFor = indexesFor(gpa);
            let i1 = indexFor.pt;
            let i2 = indexFor.pd;
            let i3 = indexFor.pdpt;
            let i4 = indexFor.pml4;

            // Exit once GPA exceeds its max value (48bit-width).
            if (gpa > 0xffff_ffff_f000) {
                break;
            }

            // Pick and check PML4e.
            pageSize = SIZE_512GB;
            let pml4e = pml4.entries[i4];
            if (!pml4e.flags.present()) {
                continue;
            }

            // Pick and check PDPTe.
            pageSize = SIZE_1GB;
            let pdpt = pml4e.nextTable;
            let pdpte = pdpt.entries[i3];
            if (!pdpte.flags.present()) {
                continue;
            }

            if (pdpte.flags.large) {
                let flags = getEffectiveFlags(pml4e, pdpte);
                regions.push(new Region(gpa, pdpte.pfn << 12n, flags, pageSize));
                continue;
            }

            // Pick and check PDe.
            pageSize = SIZE_2MB;
            let pd = pdpte.nextTable;
            let pde = pd.entries[i2];
            if (!pde.flags.present()) {
                continue;
            }

            if (pde.flags.large) {
                let flags = getEffectiveFlags(pml4e, pdpte, pde);
                regions.push(new Region(gpa, pde.pfn << 12n, flags, pageSize));
                continue;
            }

            // Pick and check PTe.
            pageSize = SIZE_4KB;
            let pt = pde.nextTable;
            let pte = pt.entries[i1];
            if (!pte.flags.present()) {
                continue;
            }

            let flags = getEffectiveFlags(pml4e, pdpte, pde, pte);
            regions.push(new Region(gpa, pte.pfn << 12n, flags, pageSize));
        }

        this.ncr3 = ncr3;
        this.regions = regions;

        // Computes the effective flag value from the given paging structure entries.
        // The large bit is always reported as 0.
        function getEffectiveFlags(pml4e, pdpte, pde, pte) {
            let flags = new PsFlags(0);
            flags.valid = pml4e.flags.valid & pdpte.flags.valid;
            flags.write = pml4e.flags.write & pdpte.flags.write;
            flags.user = pml4e.flags.user & pdpte.flags.user;
            flags.nonExecute = pml4e.flags.nonExecute | pdpte.flags.nonExecute;

            let allNonLeafWritable = pml4e.flags.write;
            let leaf = pdpte;
            if (pde) {
                allNonLeafWritable &= leaf.flags.write;
                leaf = pde;
                flags.valid &= pde.flags.valid;
                flags.write &= pde.flags.write;
                flags.user &= pde.flags.user;
                flags.nonExecute |= pde.flags.nonExecute;
            }
            if (pte) {
                allNonLeafWritable &= leaf.flags.write;
                leaf = pte;
                flags.valid &= pte.flags.valid;
                flags.write &= pte.flags.write;
                flags.user &= pte.flags.user;
                flags.nonExecute |= pte.flags.nonExecute;
            }
            flags.supervisorShadowStack = leaf.flags.nonExecute && !leaf.flags.user && allNonLeafWritable;
            return flags;
        }
    }

    dump(verbosity) {
        println(`N_CR3 @ ${hex(this.ncr3)}`);
        println("GPA [begin, end)               PA           Flags");
        if (verbosity > 1) {
            // Just dump all regions.
            this.regions.map(println);
        } else {
            // Combine regions that are effectively contiguous.
            let combinedRegion = null;
            for (let region of this.regions) {
                if (combinedRegion === null) {
                    combinedRegion = region;
                    continue;
                }

                // Is this region contiguous to the current region? That is, both
                // identity mapped, have the same flags and corresponding GPAs are
                // contiguous.
                if (combinedRegion.identityMapping &&
                    region.identityMapping &&
                    combinedRegion.flags.toString() == region.flags.toString() &&
                    combinedRegion.gpa + combinedRegion.size == region.gpa) {
                    // It is contiguous. Just expand the size.
                    combinedRegion.size += region.size;
                } else {
                    // It is not contiguous. Display the current region.
                    println(combinedRegion);

                    // See if there is an unmapped regions before this region.
                    if (verbosity > 0 &&
                        combinedRegion.gpa + combinedRegion.size != region.gpa) {
                        //  Yes, there is. Display that.
                        let unmappedBase = combinedRegion.gpa + combinedRegion.size;
                        let unmappedSize = region.gpa - unmappedBase;

                        let begin = hex(unmappedBase).padStart(12);
                        let end = hex(unmappedBase + unmappedSize).padStart(12);
                        let translation = hex(unmappedBase + unmappedSize).padStart(12);
                        println(`${begin} - ${end} -> ${translation} ${new PsFlags(0)}`);
                    }

                    // Move on, and start checking contiguous regions from this region.
                    combinedRegion = region;
                }
            }

            // Display the last one.
            println(combinedRegion);
        }
    }
}

// Represents a single paging structure (PS) entry for any level of the tables.
// See: Figure 5-23. 4-Kbyte PTE-Long Mode
class PsEntry {
    constructor(entry, allNonLeafWritable, nextTableType) {
        this.value = entry;
        this.flags = new PsFlags(entry, allNonLeafWritable);
        this.pfn = bits(entry, 12, 40);
        if (this.flags.present() && !this.flags.large && nextTableType !== undefined) {
            this.nextTable = new nextTableType(this.pfn << 12n);
        }
    }

    toString() {
        return hex(this.pfn) + " " + this.flags;
    }
}

// Partial representation of flag bits in any paging structure (PS) entry.
// Only bits we care are represented.
class PsFlags {
    constructor(entry, allNonLeafWritable) {
        this.valid = Boolean(bits(entry, 0, 1));
        this.write = Boolean(bits(entry, 1, 1));
        this.user = Boolean(bits(entry, 2, 1));
        this.accessed = Boolean(bits(entry, 5, 1));
        this.dirty = Boolean(bits(entry, 6, 1));
        this.large = Boolean(bits(entry, 7, 1));
        this.nonExecute = Boolean(bits(entry, 63, 1));
        // 15.25.14 Supervisor Shadow Stacks
        this.supervisorShadowStack = this.nonExecute && !this.user && allNonLeafWritable;
    }

    toString() {
        if (!this.valid) {
            return "----------";
        }
        return (
            (this.supervisorShadowStack ? "S" : "-") +
            (this.large ? "L" : "-") +
            (this.dirty ? "D" : "-") +
            (this.accessed ? "A" : "-") +
            "--" +
            (this.user ? "U" : "K") +
            (this.write ? "W" : "R") +
            (this.nonExecute ? "-" : "E") +
            (this.valid ? "V" : "-")
        );
    }

    present() {
        return this.valid;
    }
}

class Pml4 {
    constructor(address) {
        this.address = address;
        this.entries = readPageAsPsTable(address, Pdpt);
    }
}

class Pdpt {
    constructor(address) {
        this.address = address;
        this.entries = readPageAsPsTable(address, Pd);
    }
}

class Pd {
    constructor(address) {
        this.address = address;
        this.entries = readPageAsPsTable(address, Pt);
    }
}

class Pt {
    constructor(address) {
        this.address = address;
        this.entries = readPageAsPsTable(address);
    }
}

// Reads a physical address for 4KB and constructs a table with 512 entries.
function readPageAsPsTable(address, nextTableType) {
    let entries = [];
    parseEach16Bytes(address & ~0xfffn, 0x100, (l, h) =>
        entries.push(new PsEntry(l, undefined, nextTableType), new PsEntry(h, undefined, nextTableType)));
    return entries;
}

// The layout of VMCB, as of the revision 3.42, March 2024.
// See: Appendix B VMCB Layout
const VMCB_LAYOUT = {
    // See: Table B-1. VMCB Layout, Control Area
    0x000: [GenericU16, "Intercept reads of CR0-15"],
    0x002: [GenericU16, "Intercept writes of CR0-15"],
    0x004: [GenericU16, "Intercept writes of DR0-15"],
    0x006: [GenericU16, "Intercept writes of DR0-15"],
    0x008: [GenericU32, "Intercept exception vectors 0-31"],
    0x00c: [GenericU32, "Intercept misc1"],
    0x010: [GenericU32, "Intercept misc2"],
    0x014: [GenericU32, "Intercept misc3"],
    0x03c: [GenericU16, "PAUSE Filter Threshold"],
    0x03e: [GenericU16, "PAUSE Filter Count"],
    0x040: [IopmBasePa, "IOPM_BASE_PA"],
    0x048: [MsrpmBasePa, "MSRPM_BASE_PA"],
    0x050: [GenericU64, "TSC_OFFSET"],
    0x058: [GenericU32, "Guest ASID"],
    0x05c: [GenericU32, "TLB_CONTROL"],
    0x060: [GenericU64, "Virtual interrupt"],
    0x068: [GenericU64, "Interrupt shadow"],
    0x070: [GenericU64, "EXITCODE"],
    0x078: [GenericU64, "EXITINFO1"],
    0x080: [GenericU64, "EXITINFO2"],
    0x088: [GenericU64, "EXITINTINFO"],
    0x090: [GenericU64, "Nested paging"],
    0x098: [GenericU64, "AVIC APIC_BAR"],
    0x0a0: [GenericU64, "Guest physical address of GHCB"],
    0x0a8: [GenericU64, "EVENTINJ"],
    0x0b0: [Ncr3, "N_CR3"],
    0x0b8: [GenericU64, "Virtualize misc instructions"],
    0x0c0: [GenericU64, "VMCB Clean Bits"],
    0x0c8: [GenericU64, "nRIP"],
    0x0d0: [GenericU8, "Number of bytes fetched"],
    0x0d1: [Array15U8, "Guest instruction bytes"],
    0x0e0: [GenericU64, "AVIC APIC_BACKING_PAGE Pointer"],
    0x0f0: [GenericU64, "AVIC LOGICAL_TABLE Pointer"],
    0x0f8: [GenericU8, "AVIC_PHYSICAL_MAX_INDEX"],
    0x0f9: [GenericU64, "AVIC PHYSICAL_TABLE Pointer"],
    0x108: [GenericU64, "VMSA Pointer"],
    0x110: [GenericU64, "VMGEXIT_RAX"],
    0x118: [GenericU8, "VMGEXIT_CPL"],
    0x120: [GenericU16, "Bus Lock Threshold Counter"],
    0x134: [GenericU32, "UPDATE_IRR"],
    0x138: [GenericU64, "ALLOWED_SEV_FEATURES"],
    0x140: [GenericU64, "GUEST_SEV_FEATURES"],
    0x150: [Array32U8, "REQUESTED_IRR"],

    // See: Table B-2. VMCB Layout, State Save Area
    0x400: [GenericU16, "ES selector"],
    0x402: [GenericU16, "ES attrib"],
    0x404: [GenericU32, "ES limit"],
    0x408: [GenericU64, "ES base"],
    0x400: [GenericU16, "CS selector"],
    0x402: [GenericU16, "CS attrib"],
    0x404: [GenericU32, "CS limit"],
    0x408: [GenericU64, "CS base"],
    0x400: [GenericU16, "SS selector"],
    0x402: [GenericU16, "SS attrib"],
    0x404: [GenericU32, "SS limit"],
    0x408: [GenericU64, "SS base"],
    0x400: [GenericU16, "DS selector"],
    0x402: [GenericU16, "DS attrib"],
    0x404: [GenericU32, "DS limit"],
    0x408: [GenericU64, "DS base"],
    0x400: [GenericU16, "FS selector"],
    0x402: [GenericU16, "FS attrib"],
    0x404: [GenericU32, "FS limit"],
    0x408: [GenericU64, "FS base"],
    0x400: [GenericU16, "GS selector"],
    0x402: [GenericU16, "GS attrib"],
    0x404: [GenericU32, "GS limit"],
    0x408: [GenericU64, "GS base"],
    0x400: [GenericU16, "GDTR selector"],
    0x402: [GenericU16, "GDTR attrib"],
    0x404: [GenericU32, "GDTR limit"],
    0x408: [GenericU64, "GDTR base"],
    0x400: [GenericU16, "LDTR selector"],
    0x402: [GenericU16, "LDTR attrib"],
    0x404: [GenericU32, "LDTR limit"],
    0x408: [GenericU64, "LDTR base"],
    0x400: [GenericU16, "IDTR selector"],
    0x402: [GenericU16, "IDTR attrib"],
    0x404: [GenericU32, "IDTR limit"],
    0x408: [GenericU64, "IDTR base"],
    0x400: [GenericU16, "TR selector"],
    0x402: [GenericU16, "TR attrib"],
    0x404: [GenericU32, "TR limit"],
    0x408: [GenericU64, "TR base"],
    0x4cb: [GenericU8, "CPL"],
    0x4d0: [GenericU64, "EFER"],
    0x4e0: [GenericU64, "PERF_CTL0"],
    0x4e8: [GenericU64, "PERF_CTR0"],
    0x4f0: [GenericU64, "PERF_CTL1"],
    0x4f8: [GenericU64, "PERF_CTR1"],
    0x500: [GenericU64, "PERF_CTL2"],
    0x508: [GenericU64, "PERF_CTR2"],
    0x510: [GenericU64, "PERF_CTL3"],
    0x518: [GenericU64, "PERF_CTR3"],
    0x520: [GenericU64, "PERF_CTL4"],
    0x528: [GenericU64, "PERF_CTR4"],
    0x530: [GenericU64, "PERF_CTL5"],
    0x538: [GenericU64, "PERF_CTR5"],
    0x548: [GenericU64, "CR4"],
    0x550: [GenericU64, "CR3"],
    0x558: [GenericU64, "CR0"],
    0x560: [GenericU64, "DR7"],
    0x568: [GenericU64, "DR6"],
    0x570: [GenericU64, "RFLAGS"],
    0x578: [GenericU64, "RIP"],
    0x5c0: [GenericU64, "INSTR_RETIRED_CTR"],
    0x5c8: [GenericU64, "PERF_CTR_GLOBAL_STS"],
    0x5d0: [GenericU64, "PERF_CTR_GLOBAL_CTL"],
    0x5d8: [GenericU64, "RSP"],
    0x5e0: [GenericU64, "S_CET"],
    0x5e8: [GenericU64, "SSP"],
    0x5f0: [GenericU64, "ISST_ADDR"],
    0x5f8: [GenericU64, "RAX"],
    0x600: [GenericU64, "STAR"],
    0x608: [GenericU64, "LSTAR"],
    0x610: [GenericU64, "CSTAR"],
    0x618: [GenericU64, "SFMASK"],
    0x620: [GenericU64, "KernelGsBase"],
    0x628: [GenericU64, "SYSENTER_CS"],
    0x630: [GenericU64, "SYSENTER_ESP"],
    0x638: [GenericU64, "SYSENTER_EIP"],
    0x640: [GenericU64, "CR2"],
    0x668: [GenericU64, "G_PAT"],
    0x670: [GenericU64, "DBGCTL"],
    0x678: [GenericU64, "BR_FROM"],
    0x680: [GenericU64, "BR_TO"],
    0x688: [GenericU64, "LASTEXCPFROM"],
    0x690: [GenericU64, "LASTEXCPTO"],
    0x698: [GenericU64, "DBGEXTNCTL"],
    0x6e0: [GenericU64, "SPEC_CTRL"],
    0xa70: [Array256U8, "LBR_STACK_FROM_TO"],
    0xb70: [GenericU64, "LBR_SELECT"],
    0xb78: [GenericU64, "IBS_FETCH_CTL"],
    0xb80: [GenericU64, "IBS_FETCH_LINADDR"],
    0xb88: [GenericU64, "IBS_OP_CTL"],
    0xb90: [GenericU64, "IBS_OP_RIP"],
    0xb98: [GenericU64, "IBS_OP_DATA"],
    0xba0: [GenericU64, "IBS_OP_DATA2"],
    0xba8: [GenericU64, "IBS_OP_DATA3"],
    0xbb0: [GenericU64, "IBS_DC_LINADDR"],
    0xbb8: [GenericU64, "BP_IBSTGT_RIP"],
    0xbc0: [GenericU64, "IC_IBS_EXTD_CTL"],
};

// Reads the specified physical memory address for bytes as specified in `size`.
function readPhysical(address, size) {
    assert(size % 8 == 0, "The size must be power of 8");

    let bytes = [];
    parseEach16Bytes(address, size / 8, (low, high) =>
        bytes = bytes.concat(bigIntToByteArray(low)).concat(bigIntToByteArray(high)));
    return bytes;

    // Converts a BigInt into a byte array.
    function bigIntToByteArray(number) {
        let bytes = [];
        for (let i = 0n; i < 8; ++i) {
            bytes.push((number >> (i * 8n)) & 0xffn);
        }
        return bytes;
    }
}

// Asserts that the value is a BigInt that fits in 64bit-width.
function assertOnValue(value, size) {
    assert(typeof value == "bigint", "Not a bigint");
    assert((size == 8) || (value < 1n << BigInt(size * 8)),
        "The integer too large for the size");
}

// Takes specified range of bits from the 64bit value.
function bits(value, offset, size) {
    assert(offset + size <= 64, `Invalid offset and size: ${offset}, ${size}`);
    let mask = (1n << BigInt(size)) - 1n;
    return (BigInt(value) >> BigInt(offset)) & mask;
}

// Parses 16 bytes at the given physical address into two 8 byte integers.
function parseEach16Bytes(pa, count, callback) {
    for (let line of exec(`!dq ${hex(pa)} l${hex(count * 2)}`)) {
        let values = line.replace(/`/g, "").substring(10).trim().split(" ");
        try {
            var low = BigInt("0x" + values[0]);
            var high = BigInt("0x" + values[1]);
        } catch (error) {
            throw new Error("Failed to parse: " + line);
        }
        callback(low, high);
    }
}

const print = msg => host.diagnostics.debugLog(msg);
const println = msg => print(msg + "\n");
const hex = (num, padding = 0) => "0x" + num.toString(16).padStart(padding, "0");
const exec = cmd => host.namespace.Debugger.Utility.Control.ExecuteCommand(cmd);
const assert = (expr, msg = "Assertion failed") => { if (!expr) { throw Error(msg); } };
const toInt64 = bigint => host.Int64(Number(bigint & 0xffff_ffffn), Number(bigint >> 32n));
