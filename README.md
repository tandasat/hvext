# hvext

The Windbg extension that implements commands helpful to study Hyper-V on Intel processors.

## Usage

1. Attach a debugger to Hyper-V on a target. See [Setting up KDNET over USB EEM for Bootloader and Hyper-V debugging](https://tandasat.github.io/blog/windows/2023/03/21/setting-up-kdnet-over-usb-eem-for-bootloader-and-hyper-v-debugging.html) for details.

2. Let the target run if the debugger breaks-in at initial connection. This extension does not function at this stage since processors are not in VMX root operation yet.

3. Break-in the target Hyper-V.

4. Load the script, for example:
    ```
    kd> .scriptrun C:\Users\user\Desktop\hvext\hvext.js
    JavaScript script successfully loaded from 'C:\Users\user\Desktop\hvext\hvext.js'
    hvext loaded. Execute !hvext_help [command] for help.
    ```

5. Execute commands.
    ```
    kd> !hvext_help
    hvext_help [command] - Displays this message.
    dump_dmar [pa] - Displays status and configurations of a DMA remapping unit.
    dump_ept [verbosity] - Displays guest physical address translation managed through EPT.
    dump_hlat [verbosity] - Displays linear address translation managed through HLAT.
    dump_io - Displays contents of the IO bitmaps.
    dump_msr [verbosity] - Displays contents of the MSR bitmaps.
    dump_vmcs - Displays contents of the current VMCS.
    ept_pte [gpa] - Displays contents of EPT entries used to translated the given GPA.
    indexes [address] - Displays index values to walk paging structures for the given address.
    pte [la] - Displays contents of paging structure entries used to translated the given LA.

    Note: When executing some of those commands, the processor must be in VMX-root operation with an active VMCS.
    ```

If you encounter stability issues, consider making the target a single core with:
```
> bcdedit /set numproc 1
```

## References and acknowledgement
- [@ergot86's implementation](https://github.com/ergot86/crap/blob/main/hyperv_stuff.js) as the base of this script.
- [@0vercl0k's amazing introduction](https://doar-e.github.io/blog/2017/12/01/debugger-data-model/) to Windbg Preview, including authoring extensions.
- [@gerhart_x's IDA Python scripts](https://github.com/gerhart01/Hyper-V-scripts/blob/master/display-vmcs.py) for IDA Pro users (instead of Windbg).
