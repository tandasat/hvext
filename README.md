# hvext

The Windbg extension that implements commands helpful to study Hyper-V on Intel processors.

## Usage

1. Attach a debugger to Hyper-V on a target. See [Setting up KDNET over USB EEM for Bootloader and Hyper-V debugging](https://tandasat.github.io/blog/windows/2023/03/21/setting-up-kdnet-over-usb-eem-for-bootloader-and-hyper-v-debugging.html) for details.

2. Let the target boot until the Windows logon screen. This extension does not function at the stage of the first few break-ins, since processors are not in VMX root operation yet.

3. Break-in the target Hyper-V.

4. Load the script, for example:
    ```
    10: kd> .scriptrun C:\Users\user\Desktop\hvext\hvext.js
    JavaScript script successfully loaded from 'C:\Users\user\Desktop\hvext\hvext.js'
    hvext loaded. Execute !hvext_help [command] for help.
    ```

5. Execute commands.
    ```
    10: kd> !hvext_help
    hvext_help [command] - Displays this message.
    dump_ept [verbosity] - Displays contents of the EPT translation for the current EPTP.
    dump_vmcs - Displays contents of all VMCS encodings for ths current VMCS.
    indexes [gpa] - Displays index values walk EPT for the given GPA.
    pte [gpa] - Displays contents of EPT entries used to translated the given GPA.

    Note: When executing those commands, the processor must be in VMX-root operation with an active VMCS.
    ```

## References and acknowledgement
- [@ergot86's implementation](https://github.com/ergot86/crap/blob/main/hyperv_stuff.js) as the base of this script.
- [@0vercl0k's amazing introduction](https://doar-e.github.io/blog/2017/12/01/debugger-data-model/) to Windbg Preview, including authoring extensions.
- [@gerhart_x's IDA Python scripts](https://github.com/gerhart01/Hyper-V-scripts/blob/master/display-vmcs.py) for IDA Pro users (instead of Windbg).
