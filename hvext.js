﻿"use strict";

// Registers commands.
function initializeScript() {
    return [
        new host.apiVersionSupport(1, 7),
        new host.functionAlias(hvextHelp, "hvext_help"),
        new host.functionAlias(dumpEpt, "dump_ept"),
        new host.functionAlias(dumpMsr, "dump_msr"),
        new host.functionAlias(dumpVmcs, "dump_vmcs"),
        new host.functionAlias(eptPte, "ept_pte"),
        new host.functionAlias(indexesFor, "indexes"),
        new host.functionAlias(pte, "pte"),
    ];
}

// Cache of fully-parsed EPT, keyed by EPTP.
var g_eptCache = {};

// The virtual address of (the first) "VMREAD RAX, RAX" in the HV image range.
var g_vmreadAddress = null;

// Initializes the extension.
function invokeScript() {
    exec(".load kext");
    g_vmreadAddress = findFirstVmreadRaxRax();
    println("hvext loaded. Execute !hvext_help [command] for help.");

    // Returns the first virtual address with "VMREAD RAX, RAX" in the HV address range.
    function findFirstVmreadRaxRax() {
        const isVmreadRaxRax = (memory, i) => (
            memory[i] == 0x0f &&
            memory[i + 1] == 0x78 &&
            memory[i + 2] == 0xc0
        );

        // Search each page in the HV image range. Returns the first hit.
        let hvImageRange = findHvImageRange();
        for (let i = hvImageRange.Start; i.compareTo(hvImageRange.End) == -1; i = i.add(0x1000)) {
            let found = searchMemory(i, 0x1000, isVmreadRaxRax);
            if (found.length != 0) {
                return found[0];
            }
        }
        throw new Error("No VMREAD RAX, RAX (0f 78 c0) found.");

        // Returns the range of the virtual address where the HV image is mapped.
        function findHvImageRange() {
            // Get the range with "lm".
            // eg: fffff876`b89e0000 fffff876`b8de2000   hv         (no symbols)
            let chunks = exec("lm m hv").Last().split(" ");
            let start = chunks[0].replace("`", "");
            let end = chunks[1].replace("`", "");
            return {
                "Start": host.parseInt64(start, 16),
                "End": host.parseInt64(end, 16),
            };
        }

        // Finds an array of virtual addresses that matches the specified condition.
        function searchMemory(address, bytes, predicate) {
            // Memory read can fail if the address is not mapped.
            try {
                var memory = host.memory.readMemoryValues(address, bytes);
            } catch (error) {
                return [];
            }

            let index = [];
            for (let i = 0; i < bytes; i++) {
                if (predicate(memory, i)) {
                    index.push(address.add(i));
                }
            }
            return index;
        }
    }
}

// Implements the !hvext_help command.
function hvextHelp(command) {
    switch (command) {
        case "dump_ept":
            println("dump_ept [verbosity] - Displays contents of the EPT translation for the current EPTP.");
            println("   verbosity - 0 = Shows valid translations in a summarized format (default).");
            println("               1 = Shows both valid and invalid translations in a summarized format.");
            println("               2 = Shows every valid translations without summarizing it.");
            break;
        case "dump_msr":
            println("dump_msr [verbosity] - Displays contents of the MSR bitmaps.");
            println("   verbosity - 0 = Shows only MSRs that are not read or write protected (default).");
            println("               1 = Shows protections of all MSRs managed by the MSR bitmaps.");
            break;
        case "dump_vmcs":
            println("dump_vmcs - Displays contents of all VMCS encodings for ths current VMCS.");
            break;
        case "ept_pte":
            println("ept_pte [gpa] - Displays contents of EPT entries used to translated the given GPA");
            println("   gpa - A GPA to translate with EPT (default= 0).");
            break;
        case "indexes":
            println("indexes [address] - Displays index values to walk paging structures for the given address.");
            println("   gpa - A GPA to decode (default= 0).");
            break;
        case "pte":
            println("pte [la] - Displays contents of paging structure entries used to translated the given LA.");
            println("   la - A LA to translate with the paging structures (default= 0).");
            break;
        case undefined:
        default:
            println("hvext_help [command] - Displays this message.");
            println("dump_ept [verbosity] - Displays contents of the EPT translation for the current EPTP.");
            println("dump_msr [verbosity] - Displays contents of the MSR bitmaps.");
            println("dump_vmcs - Displays contents of all VMCS encodings for ths current VMCS.");
            println("ept_pte [gpa] - Displays contents of EPT entries used to translated the given GPA.");
            println("indexes [address] - Displays index values to walk paging structures for the given address.");
            println("pte [la] - Displays contents of paging structure entries used to translated the given LA.");
            println("");
            println("Note: When executing those commands, the processor must be in VMX-root operation with an active VMCS.");
            println("      Many of the commands may corrupt system state and put it into an uncontainable situation.");
            break;
    }
}

// Implements the !dump_ept command.
function dumpEpt(verbosity = 0) {
    class Region {
        constructor(gpa, pa, flags, size) {
            this.gpa = gpa;
            this.pa = pa;
            this.flags = flags;
            this.size = size;
            this.identifyMapping = (gpa == pa);
        }

        toString() {
            // If this is identify mapping, display so instead of actual PA.
            let translation = (current_region.identifyMapping) ?
                "Identity".padEnd(12) :
                hex(current_region.pa).padStart(12);

            return hex(current_region.gpa).padStart(12) + " - " +
                hex(current_region.gpa + current_region.size).padStart(12) + " -> " +
                translation + " " +
                current_region.flags;
        }
    }

    const SIZE_4KB = 0x1000;
    const SIZE_2MB = 0x200000;
    const SIZE_1GB = 0x40000000;
    const SIZE_512GB = 0x8000000000;

    let pml4 = getCurrentEptPml4();

    // Walk through all EPT entries and accumulate them as regions.
    let regions = [];
    for (var gpa = 0, page_size = 0; ; gpa += page_size) {
        let indexFor = indexesFor(gpa);
        let i1 = indexFor.Pt;
        let i2 = indexFor.Pd;
        let i3 = indexFor.Pdpt;
        let i4 = indexFor.Pml4;

        // Exit once GPA exceeds its max value (48bit-width).
        if (gpa > 0xfffffffff000) {
            break;
        }

        // Pick and check PML4e.
        page_size = SIZE_512GB;
        let pml4e = pml4.entries[i4];
        if (!pml4e.flags.present()) {
            continue;
        }

        // Pick and check PDPTe.
        page_size = SIZE_1GB;
        let pdpt = pml4e.nextTable;
        let pdpte = pdpt.entries[i3];
        if (!pdpte.flags.present()) {
            continue;
        }

        if (pdpte.flags.large) {
            let flags = getEffectiveFlags(pml4e, pdpte);
            regions.push(new Region(gpa, pdpte.pfn.bitwiseShiftLeft(12), flags, page_size));
            continue;
        }

        // Pick and check PDe.
        page_size = SIZE_2MB;
        let pd = pdpte.nextTable;
        let pde = pd.entries[i2];
        if (!pde.flags.present()) {
            continue;
        }

        if (pde.flags.large) {
            let flags = getEffectiveFlags(pml4e, pdpte, pde);
            regions.push(new Region(gpa, pde.pfn.bitwiseShiftLeft(12), flags, page_size));
            continue;
        }

        // Pick and check PTe.
        page_size = SIZE_4KB;
        let pt = pde.nextTable;
        let pte = pt.entries[i1];
        if (!pte.flags.present()) {
            continue;
        }

        let flags = getEffectiveFlags(pml4e, pdpte, pde, pte);
        regions.push(new Region(gpa, pte.pfn.bitwiseShiftLeft(12), flags, page_size));
    }

    // Display gathered regions.
    if (verbosity == 2) {
        // Just dump all regions.
        println("GPA             PA           Flags");
        for (let region of regions) {
            println(hex(region.gpa).padStart(12) + " -> " +
                hex(region.pa).padStart(12) + " " +
                region.flags);
        }
    } else {
        println("GPA                            PA           Flags");

        // Combine regions that are effectively contiguous.
        var current_region = null;
        for (let region of regions) {
            if (current_region === null) {
                current_region = region;
                continue;
            }

            // Is this region contiguous to the current region? That is, both
            // identify mapped, have the same flags and corresponding GPAs are
            // contiguous.
            if (current_region.identifyMapping &&
                region.identifyMapping &&
                current_region.flags.toString() == region.flags.toString() &&
                current_region.gpa + current_region.size == region.gpa) {
                // It is contiguous. Just expand the size.
                current_region.size += region.size;
            } else {
                // It is not. Display the current region.
                println(current_region);

                // If not, see if there is an unmapped regions before this region.
                if (verbosity == 1 &&
                    current_region.gpa + current_region.size != region.gpa) {
                    //  Yes, there is. Display that.
                    let unmapped_base = current_region.gpa + current_region.size;
                    let unmapped_size = region.gpa - unmapped_base;
                    println(hex(unmapped_base).padStart(12) + " - " +
                        hex(unmapped_base + unmapped_size).padStart(12) + " -> " +
                        "Unmapped".padEnd(12) + " " +
                        new EptFlags(0));
                }

                // Move on, and start checking contiguous regions from this region.
                current_region = region;
            }
        }

        // Display the last one.
        println(current_region);
    }

    // Computes the effective flag value from the given EPT entries. The large bit
    // is always reported as 0.
    function getEffectiveFlags(pml4e, pdpte, pde, pte) {
        let flags = new EptFlags(0);
        flags.read = pml4e.flags.read & pdpte.flags.read;
        flags.write = pml4e.flags.write & pdpte.flags.write;
        flags.execute = pml4e.flags.execute & pdpte.flags.execute;
        flags.executeForUserMode = pml4e.flags.executeForUserMode & pdpte.flags.executeForUserMode;

        var leaf = pdpte;
        if (pde) {
            leaf = pde;
            flags.read &= pde.flags.read;
            flags.write &= pde.flags.write;
            flags.execute &= pde.flags.execute;
            flags.executeForUserMode &= pde.flags.executeForUserMode;
        }
        if (pte) {
            leaf = pte;
            flags.read &= pte.flags.read;
            flags.write &= pte.flags.write;
            flags.execute &= pte.flags.execute;
            flags.executeForUserMode &= pte.flags.executeForUserMode;
        }
        flags.memoryType = leaf.flags.memoryType;
        flags.verifyGuestPaging = leaf.flags.verifyGuestPaging;
        flags.pagingWriteAccess = leaf.flags.pagingWriteAccess;
        flags.supervisorShadowStack = leaf.flags.supervisorShadowStack;
        return flags;
    }
}

// Implements the !dump_msr command.
function dumpMsr(verbosity = 0) {
    class MsrEntry {
        constructor(bit_position, read_protected, write_protected) {
            if (bit_position < 0x2000) {
                this.msr = bit_position;
            } else {
                this.msr = bit_position - 0x2000 + 0xc0000000;
            }
            this.read_protected = read_protected;
            this.write_protected = write_protected;
        }

        toString() {
            return (
                { 1: "-", 0: "R" }[this.read_protected] +
                { 1: "-", 0: "W" }[this.write_protected] +
                " " +
                hex(this.msr)
            );
        }
    }

    let bitmap = readVmcs(0x00002004);  // MSR bitmaps

    // Convert the 4KB contents into an array of 64bit integers for processing.
    let entries = [];
    for (let line of exec("!dq " + hex(bitmap.bitwiseAnd(~0xfff)) + " l200")) {
        let values = line.replace(/`/g, "").substring(10).trim().split(" ");
        entries.push(host.parseInt64(values[0], 16));
        entries.push(host.parseInt64(values[1], 16));
    }

    // The MSR bitmaps are made up of two 2048 bytes segments. The first segment
    // manages read access, and the 2nd manages write access, for the same ranges
    // of MSRs. Let us walk the half of the `entries` and add offset 2048
    // (= 0x100 * 8) to look both segments in a single loop.
    let msrs = [];
    for (let i = 0; i < 0x100; i += 1) {
        let entry_low = entries[i];
        let entry_hi = entries[i + 0x100];
        // For the selected upper and lower 64bit entries, walk though each bit
        // position and construct `MsrEntry` from the pair of the bits.
        for (let bit_position = 0; bit_position < 64; bit_position += 1) {
            let read_protected = bits(entry_low, bit_position, 1).asNumber();
            let write_protected = bits(entry_hi, bit_position, 1).asNumber();
            msrs.push(new MsrEntry(i * 64 + bit_position, read_protected, write_protected));
        }
    }

    for (let msr of msrs) {
        if (verbosity == 0) {
            if (!msr.read_protected || !msr.write_protected) {
                println(msr);
            }
        } else {
            println(msr);
        }
    }
}

// Implements the !dump_vmcs command.
function dumpVmcs() {
    // Capture the current state.
    let originalRax = host.currentThread.Registers.User.rax.toString(16);
    let originalRip = host.currentThread.Registers.User.rip.toString(16);
    let originalRflags = host.currentThread.Registers.User.efl.toString(16);

    // Loop over the VMCS encodings.
    for (let i = 0; i < VMCS_ENCODINGS.length; i += 2) {
        let name = VMCS_ENCODINGS[i];
        let encoding = VMCS_ENCODINGS[i + 1];
        let value = readVmcsUnsafe(encoding);
        if (value === undefined) {
            println("***** FAILED *****" + " " + name);
        } else {
            println(hex(value, 16) + " " + name);
        }
    }

    // All done. Restore the original state.
    exec("r rax=" + originalRax + ", " +
        "rip=" + originalRip + ", " +
        "efl=" + originalRflags);
}

// Implements the !ept_pte command.
function eptPte(gpa) {
    if (gpa == undefined) {
        gpa = 0;
    }

    let indexFor = indexesFor(gpa);
    let i1 = indexFor.Pt;
    let i2 = indexFor.Pd;
    let i3 = indexFor.Pdpt;
    let i4 = indexFor.Pml4;

    // Pick and check PML4e.
    let pml4 = getCurrentEptPml4();
    let pml4e = pml4.entries[i4];
    if (!pml4e.flags.present()) {
        println("PML4e at " + hex(pml4.address.add(8 * i4)));
        println("contains " + hex(pml4e.value));
        println("pfn " + pml4e);
        return;
    }

    // Pick and check PDPTe.
    let pdpt = pml4e.nextTable;
    let pdpte = pdpt.entries[i3];
    if (!pdpte.flags.present() || pdpte.flags.large) {
        println("PML4e at " + hex(pml4.address.add(8 * i4)) + "     " +
            "PDPTe at " + hex(pdpt.address.add(8 * i3)));
        println("contains " + hex(pml4e.value) + "     " +
            "contains " + hex(pdpte.value));
        println("pfn " + pml4e + "   " +
            "pfn " + pdpte);
        return;
    }

    // Pick and check PDe.
    let pd = pdpte.nextTable;
    let pde = pd.entries[i2];
    if (!pde.flags.present() || pde.flags.large) {
        println("PML4e at " + hex(pml4.address.add(8 * i4)) + "     " +
            "PDPTe at " + hex(pdpt.address.add(8 * i3)) + "     " +
            "PDe at " + hex(pd.address.add(8 * i2)));
        println("contains " + hex(pml4e.value) + "     " +
            "contains " + hex(pdpte.value) + "     " +
            "contains " + hex(pde.value));
        println("pfn " + pml4e + "   " +
            "pfn " + pdpte + "   " +
            "pfn " + pde);
        return;
    }

    // Pick PTe.
    let pt = pde.nextTable;
    let pte = pt.entries[i1];
    println("PML4e at " + hex(pml4.address.add(8 * i4)) + "     " +
        "PDPTe at " + hex(pdpt.address.add(8 * i3)) + "     " +
        "PDe at " + hex(pd.address.add(8 * i2)) + "       " +
        "PTe at " + hex(pt.address.add(8 * i1)));
    println("contains " + hex(pml4e.value) + "     " +
        "contains " + hex(pdpte.value) + "     " +
        "contains " + hex(pde.value) + "     " +
        "contains " + hex(pte.value));
    println("pfn " + pml4e + "   " +
        "pfn " + pdpte + "   " +
        "pfn " + pde + "   " +
        "pfn " + pte);
}

// Implements the !indexes command.
function indexesFor(gpa) {
    return {
        "Pt": bits(gpa, 12, 9).asNumber(),
        "Pd": bits(gpa, 21, 9).asNumber(),
        "Pdpt": bits(gpa, 30, 9).asNumber(),
        "Pml4": bits(gpa, 39, 9).asNumber(),
    };
}

// Implements the !pte command.
function pte(la) {
    if (la == undefined) {
        la = 0;
    }

    let indexFor = indexesFor(la);
    let i1 = indexFor.Pt;
    let i2 = indexFor.Pd;
    let i3 = indexFor.Pdpt;
    let i4 = indexFor.Pml4;

    // Pick and check PML4e.
    let pml4Address = host.currentThread.Registers.Kernel.cr3.bitwiseAnd(~0xfff);
    let pml4e = new PsEntry(readEntry(pml4Address + 8 * i4));
    if (!pml4e.flags.present()) {
        println("PML4e at " + hex(pml4Address.add(8 * i4)));
        println("contains " + hex(pml4e.value));
        println("pfn " + pml4e);
        return;
    }

    // Pick and check PDPTe.
    let pdptAddress = pml4e.pfn.bitwiseShiftLeft(12);
    let pdpte = new PsEntry(readEntry(pdptAddress + 8 * i3));
    if (!pdpte.flags.present() || pdpte.flags.large) {
        println("PML4e at " + hex(pml4Address.add(8 * i4)) + "     " +
            "PDPTe at " + hex(pdptAddress.add(8 * i3)));
        println("contains " + hex(pml4e.value) + "     " +
            "contains " + hex(pdpte.value));
        println("pfn " + pml4e + "   " +
            "pfn " + pdpte);
        return;
    }

    // Pick and check PDe.
    let pdAddress = pdpte.pfn.bitwiseShiftLeft(12);
    let pde = new PsEntry(readEntry(pdAddress + 8 * i2));
    if (!pde.flags.present() || pde.flags.large) {
        println("PML4e at " + hex(pml4Address.add(8 * i4)) + "     " +
            "PDPTe at " + hex(pdptAddress.add(8 * i3)) + "     " +
            "PDe at " + hex(pdAddress.add(8 * i2)));
        println("contains " + hex(pml4e.value) + "     " +
            "contains " + hex(pdpte.value) + "     " +
            "contains " + hex(pde.value));
        println("pfn " + pml4e + "   " +
            "pfn " + pdpte + "   " +
            "pfn " + pde);
        return;
    }

    // Pick PTe.
    let ptAddress = pde.pfn.bitwiseShiftLeft(12);
    let pte = new PsEntry(readEntry(ptAddress + 8 * i1));
    println("PML4e at " + hex(pml4Address.add(8 * i4)) + "     " +
        "PDPTe at " + hex(pdptAddress.add(8 * i3)) + "     " +
        "PDe at " + hex(pdAddress.add(8 * i2)) + "       " +
        "PTe at " + hex(ptAddress.add(8 * i1)));
    println("contains " + hex(pml4e.value) + "     " +
        "contains " + hex(pdpte.value) + "     " +
        "contains " + hex(pde.value) + "     " +
        "contains " + hex(pte.value));
    println("pfn " + pml4e + "   " +
        "pfn " + pdpte + "   " +
        "pfn " + pde + "   " +
        "pfn " + pte);

    function readEntry(address) {
        let line = exec("!dq " + hex(address) + " l1").Last();
        return host.parseInt64(line.replace(/`/g, "").substring(10).trim().split(" "), 16);
    }
}

// Returns fully-parsed EPT entries pointed by the current EPTP VMCS encoding.
function getCurrentEptPml4() {
    let eptp = readVmcs(0x0000201A);  // EPT pointer
    if (eptp === undefined) {
        throw new Error("The VMREAD instruction failed");
    }

    println("Current EPT pointer " + hex(eptp));

    // If this EPT is already in cache, return it.
    let pml4Addr = eptp.bitwiseAnd(~0xfff);
    if (g_eptCache[pml4Addr]) {
        return g_eptCache[pml4Addr];
    }

    // Otherwise, parse it and populate cache.
    g_eptCache[pml4Addr] = new EptPml4(pml4Addr);
    return g_eptCache[pml4Addr];
}

// Reads a VMCS encoding.
function readVmcs(encoding) {
    // Capture the current state.
    let originalRax = host.currentThread.Registers.User.rax.toString(16);
    let originalRip = host.currentThread.Registers.User.rip.toString(16);
    let originalRflags = host.currentThread.Registers.User.efl.toString(16);

    let value = readVmcsUnsafe(encoding);

    // All done. Restore the original state.
    exec("r rax=" + originalRax + ", " +
        "rip=" + originalRip + ", " +
        "efl=" + originalRflags);

    return value;
}

// Reads a VMCS encoding without restoring register values.
function readVmcsUnsafe(encoding) {
    // Jump (back) to "VMREAD RAX, RAX", update RAX with encoding to read,
    // and execute the instruction.
    exec("r rip=" + hex(g_vmreadAddress) + ", rax=" + hex(encoding));
    if (exec("p").Last().includes("second chance")) {
        throw new Error("CPU exception occurred with the VMREAD instruction." +
            " Reboot the system with the .reboot command. This can happen" +
            " when the system in an early boot stage where the processor is" +
            " not in VMX operation.");
    }

    // Check whether the VMREAD instruction succeeded.
    // eg: efl=00000342 rax=0000000000000000
    let output = exec("r efl, rax").Last();
    let flags = host.parseInt64(output.substring(4, 12), 16);
    if ((flags & 0x41) == 0) {  // if CF==0 && ZF==0
        // Succeeded. RAX should contain the field value.
        return host.parseInt64(output.substring(17, 33), 16);
    } else {
        // VMREAD failed.
        return undefined;
    }
}

class EptPml4 {
    constructor(address) {
        println("PML4 " + hex(address));
        this.address = address;
        this.entries = readPageAsTable(address, EptPdpt);
    }
}

class EptPdpt {
    constructor(address) {
        println("    PDPT " + hex(address));
        this.address = address;
        this.entries = readPageAsTable(address, EptPd);
    }
}

class EptPd {
    constructor(address) {
        println("        PD " + hex(address));
        this.address = address;
        this.entries = readPageAsTable(address, EptPt);
    }
}

class EptPt {
    constructor(address) {
        println("            PT " + hex(address));
        this.address = address;
        this.entries = readPageAsTable(address);
    }
}

// Reads a physical address for 4KB and constructs a table with 512 EPT entries.
function readPageAsTable(address, nextTableType) {
    let entries = [];
    for (let line of exec("!dq " + hex(address.bitwiseAnd(~0xfff)) + " l200")) {
        let values = line.replace(/`/g, "").substring(10).trim().split(" ");
        entries.push(new EptEntry(host.parseInt64(values[0], 16), nextTableType));
        entries.push(new EptEntry(host.parseInt64(values[1], 16), nextTableType));
    }
    return entries;
}

// Represents a single paging structure entry for any level of the tables.
class PsEntry {
    constructor(entry) {
        this.value = entry;
        this.flags = new PsFlags(entry);
        this.pfn = bits(entry, 12, 40).asNumber();
    }

    toString() {
        return hex(this.pfn) + " " + this.flags;
    }
}

// Partial representation of flags bits in any paging structure entries. Only
// bits we care are represented.
// See: Figure 4-11. Formats of CR3 and Paging-Structure Entries with 4-Level Paging and 5-Level Paging
class PsFlags {
    constructor(entry) {
        this.valid = bits(entry, 0, 1).asNumber();
        this.write = bits(entry, 1, 1).asNumber();
        this.user = bits(entry, 2, 1).asNumber();
        this.accessed = bits(entry, 5, 1).asNumber();
        this.dirty = bits(entry, 6, 1).asNumber();
        this.large = bits(entry, 7, 1).asNumber();
        this.nonExecute = bits(entry, 63, 1).asNumber();
    }

    toString() {
        if (!this.valid) {
            return "---------";
        }
        return (
            { 1: "L", 0: "-" }[this.large] +
            { 1: "D", 0: "-" }[this.dirty] +
            { 1: "A", 0: "-" }[this.accessed] +
            "--" +
            { 1: "U", 0: "K" }[this.user] +
            { 1: "W", 0: "R" }[this.write] +
            { 1: "-", 0: "E" }[this.nonExecute] +
            { 1: "V", 0: "-" }[this.valid]
        );
    }

    present() {
        return this.valid;
    }
}

// Represents a single EPT entry for any level of the tables.
class EptEntry {
    constructor(entry, nextTableType) {
        this.value = entry;
        this.flags = new EptFlags(entry);
        this.pfn = bits(entry, 12, 40).asNumber();
        if (this.flags.present() && !this.flags.large && nextTableType !== undefined) {
            this.nextTable = new nextTableType(this.pfn.bitwiseShiftLeft(12));
        }
    }

    toString() {
        return hex(this.pfn) + " " + this.flags;
    }
}

// Partial representation of flags bits in any EPT entries. Only bits we care are
// represented.
// See: Figure 29-1. Formats of EPTP and EPT Paging-Structure Entries
class EptFlags {
    constructor(entry) {
        this.read = bits(entry, 0, 1).asNumber();
        this.write = bits(entry, 1, 1).asNumber();
        this.execute = bits(entry, 2, 1).asNumber();
        this.memoryType = bits(entry, 3, 3).asNumber();
        this.large = bits(entry, 7, 1).asNumber();
        this.executeForUserMode = bits(entry, 10, 1).asNumber();
        this.verifyGuestPaging = bits(entry, 57, 1).asNumber();
        this.pagingWriteAccess = bits(entry, 58, 1).asNumber();
        this.supervisorShadowStack = bits(entry, 60, 1).asNumber();
    }

    toString() {
        return (
            { 1: "S", 0: "-" }[this.supervisorShadowStack] +
            { 1: "P", 0: "-" }[this.pagingWriteAccess] +
            { 1: "V", 0: "-" }[this.verifyGuestPaging] +
            { 1: "U", 0: "-" }[this.executeForUserMode] +
            { 1: "L", 0: "-" }[this.large] +
            this.memoryType +
            { 1: "X", 0: "-" }[this.execute] +
            { 1: "W", 0: "-" }[this.write] +
            { 1: "R", 0: "-" }[this.read]
        );
    }

    // Checks if translation is available. Note that the bit[10]
    // (executeForUserMode) is not consulted even if MBEC is enabled. (So, you
    // cannot create a user-mode-execute-only page.)
    present() {
        return (this.read || this.write || this.execute);
    }
}

// Takes specified range of bits from the 64bit value.
function bits(value, offset, size) {
    let mask = host.Int64(1).bitwiseShiftLeft(size).subtract(1);
    return value.bitwiseShiftRight(offset).bitwiseAnd(mask);
}

const print = msg => host.diagnostics.debugLog(msg);
const println = msg => print(msg + "\n");
const hex = (num, padding = 0) => "0x" + num.toString(16).padStart(padding, "0");
const exec = cmd => host.namespace.Debugger.Utility.Control.ExecuteCommand(cmd);

// The list of VMCS encodings as of the revision 79, March 2023.
const VMCS_ENCODINGS = [
    "Virtual-processor identifier (VPID)", 0x00000000,
    "Posted-interrupt notification vector", 0x00000002,
    "EPTP index", 0x00000004,
    "HLAT prefix size", 0x00000006,
    "Last PID-pointer", 0x00000008,
    "Guest ES selector", 0x00000800,
    "Guest CS selector", 0x00000802,
    "Guest SS selector", 0x00000804,
    "Guest DS selector", 0x00000806,
    "Guest FS selector", 0x00000808,
    "Guest GS selector", 0x0000080A,
    "Guest LDTR selector", 0x0000080C,
    "Guest TR selector", 0x0000080E,
    "Guest interrupt status", 0x00000810,
    "PML index", 0x00000812,
    "Guest UINV", 0x00000814,
    "Host ES selector", 0x00000C00,
    "Host CS selector", 0x00000C02,
    "Host SS selector", 0x00000C04,
    "Host DS selector", 0x00000C06,
    "Host FS selector", 0x00000C08,
    "Host GS selector", 0x00000C0A,
    "Host TR selector", 0x00000C0C,
    "Address of I/O bitmap A", 0x00002000,
    "Address of I/O bitmap B", 0x00002002,
    "Address of MSR bitmaps", 0x00002004,
    "VM-exit MSR-store address", 0x00002006,
    "VM-exit MSR-load address", 0x00002008,
    "VM-entry MSR-load address", 0x0000200A,
    "Executive-VMCS pointer", 0x0000200C,
    "PML address", 0x0000200E,
    "TSC offset", 0x00002010,
    "Virtual-APIC address", 0x00002012,
    "APIC-access address", 0x00002014,
    "Posted-interrupt descriptor address", 0x00002016,
    "VM-function controls", 0x00002018,
    "EPT pointer", 0x0000201A,
    "EOI-exit bitmap 0", 0x0000201C,
    "EOI-exit bitmap 1", 0x0000201E,
    "EOI-exit bitmap 2", 0x00002020,
    "EOI-exit bitmap 3", 0x00002022,
    "EPTP-list address", 0x00002024,
    "VMREAD-bitmap address", 0x00002026,
    "VMWRITE-bitmap address", 0x00002028,
    "Virtualization-exception information address", 0x0000202A,
    "XSS-exiting bitmap", 0x0000202C,
    "ENCLS-exiting bitmap", 0x0000202E,
    "Sub-page-permission-table pointer", 0x00002030,
    "TSC multiplier", 0x00002032,
    "Tertiary processor-based VM-execution controls", 0x00002034,
    "ENCLV-exiting bitmap", 0x00002036,
    "Low PASID directory address", 0x00002038,
    "High PASID directory address", 0x0000203A,
    "Shared EPT pointer", 0x0000203C,
    "PCONFIG-exiting bitmap", 0x0000203E,
    "Hypervisor-managed linear-address translation pointer", 0x00002040,
    "PID-pointer table address", 0x00002042,
    "Secondary VM-exit controls", 0x00002044,
    "Guest-physical address", 0x00002400,
    "VMCS link pointer", 0x00002800,
    "Guest IA32_DEBUGCTL", 0x00002802,
    "Guest IA32_PAT", 0x00002804,
    "Guest IA32_EFER", 0x00002806,
    "Guest IA32_PERF_GLOBAL_CTRL", 0x00002808,
    "Guest PDPTE0", 0x0000280A,
    "Guest PDPTE1", 0x0000280C,
    "Guest PDPTE2", 0x0000280E,
    "Guest PDPTE3", 0x00002810,
    "Guest IA32_BNDCFGS", 0x00002812,
    "Guest IA32_RTIT_CTL", 0x00002814,
    "Guest IA32_LBR_CTL", 0x00002816,
    "Guest IA32_PKRS", 0x00002818,
    "Host IA32_PAT", 0x00002C00,
    "Host IA32_EFER", 0x00002C02,
    "Host IA32_PERF_GLOBAL_CTRL", 0x00002C04,
    "Host IA32_PKRS", 0x00002C06,
    "Pin-based VM-execution controls", 0x00004000,
    "Primary processor-based VM-execution controls", 0x00004002,
    "Exception bitmap", 0x00004004,
    "Page-fault error-code mask", 0x00004006,
    "Page-fault error-code match", 0x00004008,
    "CR3-target count", 0x0000400A,
    "Primary VM-exit controls", 0x0000400C,
    "VM-exit MSR-store count", 0x0000400E,
    "VM-exit MSR-load count", 0x00004010,
    "VM-entry controls", 0x00004012,
    "VM-entry MSR-load count", 0x00004014,
    "VM-entry interruption-information field", 0x00004016,
    "VM-entry exception error code", 0x00004018,
    "VM-entry instruction length", 0x0000401A,
    "TPR threshold", 0x0000401C,
    "Secondary processor-based VM-execution controls", 0x0000401E,
    "PLE_Gap", 0x00004020,
    "PLE_Window", 0x00004022,
    "Instruction-timeout control", 0x00004024,
    "VM-instruction error", 0x00004400,
    "Exit reason", 0x00004402,
    "VM-exit interruption information", 0x00004404,
    "VM-exit interruption error code", 0x00004406,
    "IDT-vectoring information field", 0x00004408,
    "IDT-vectoring error code", 0x0000440A,
    "VM-exit instruction length", 0x0000440C,
    "VM-exit instruction information", 0x0000440E,
    "Guest ES limit", 0x00004800,
    "Guest CS limit", 0x00004802,
    "Guest SS limit", 0x00004804,
    "Guest DS limit", 0x00004806,
    "Guest FS limit", 0x00004808,
    "Guest GS limit", 0x0000480A,
    "Guest LDTR limit", 0x0000480C,
    "Guest TR limit", 0x0000480E,
    "Guest GDTR limit", 0x00004810,
    "Guest IDTR limit", 0x00004812,
    "Guest ES access rights", 0x00004814,
    "Guest CS access rights", 0x00004816,
    "Guest SS access rights", 0x00004818,
    "Guest DS access rights", 0x0000481A,
    "Guest FS access rights", 0x0000481C,
    "Guest GS access rights", 0x0000481E,
    "Guest LDTR access rights", 0x00004820,
    "Guest TR access rights", 0x00004822,
    "Guest interruptibility state", 0x00004824,
    "Guest activity state", 0x00004826,
    "Guest SMBASE", 0x00004828,
    "Guest IA32_SYSENTER_CS", 0x0000482A,
    "VMX-preemption timer value", 0x0000482E,
    "Host IA32_SYSENTER_CS", 0x00004C00,
    "CR0 guest/host mask", 0x00006000,
    "CR4 guest/host mask", 0x00006002,
    "CR0 read shadow", 0x00006004,
    "CR4 read shadow", 0x00006006,
    "CR3-target value 0", 0x00006008,
    "CR3-target value 1", 0x0000600A,
    "CR3-target value 2", 0x0000600C,
    "CR3-target value 3", 0x0000600E,
    "Exit qualification", 0x00006400,
    "I/O RCX", 0x00006402,
    "I/O RSI", 0x00006404,
    "I/O RDI", 0x00006406,
    "I/O RIP", 0x00006408,
    "Guest-linear address", 0x0000640A,
    "Guest CR0", 0x00006800,
    "Guest CR3", 0x00006802,
    "Guest CR4", 0x00006804,
    "Guest ES base", 0x00006806,
    "Guest CS base", 0x00006808,
    "Guest SS base", 0x0000680A,
    "Guest DS base", 0x0000680C,
    "Guest FS base", 0x0000680E,
    "Guest GS base", 0x00006810,
    "Guest LDTR base", 0x00006812,
    "Guest TR base", 0x00006814,
    "Guest GDTR base", 0x00006816,
    "Guest IDTR base", 0x00006818,
    "Guest DR7", 0x0000681A,
    "Guest RSP", 0x0000681C,
    "Guest RIP", 0x0000681E,
    "Guest RFLAGS", 0x00006820,
    "Guest pending debug exceptions", 0x00006822,
    "Guest IA32_SYSENTER_ESP", 0x00006824,
    "Guest IA32_SYSENTER_EIP", 0x00006826,
    "Guest IA32_S_CET", 0x00006828,
    "Guest SSP", 0x0000682A,
    "Guest IA32_INTERRUPT_SSP_TABLE_ADDR", 0x0000682C,
    "Host CR0", 0x00006C00,
    "Host CR3", 0x00006C02,
    "Host CR4", 0x00006C04,
    "Host FS base", 0x00006C06,
    "Host GS base", 0x00006C08,
    "Host TR base", 0x00006C0A,
    "Host GDTR base", 0x00006C0C,
    "Host IDTR base", 0x00006C0E,
    "Host IA32_SYSENTER_ESP", 0x00006C10,
    "Host IA32_SYSENTER_EIP", 0x00006C12,
    "Host RSP", 0x00006C14,
    "Host RIP", 0x00006C16,
    "Host IA32_S_CET", 0x00006C18,
    "Host SSP", 0x00006C1A,
    "Host IA32_INTERRUPT_SSP_TABLE_ADDR", 0x00006C1C,
];
