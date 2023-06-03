# hvext

The Windbg extension that implements multiple commands helpful to study Hyper-V on Intel processors.

## Usage

1. Attach a debugger to Hyper-V on a target. See [Setting up KDNET over USB EEM for Bootloader and Hyper-V debugging](https://tandasat.github.io/blog/windows/2023/03/21/setting-up-kdnet-over-usb-eem-for-bootloader-and-hyper-v-debugging.html) for details.

2. Let the target boot until the Windows logon screen. This extension does not function at the stage of the first few break-ins, since processors are not in VMX root operation yet.

3. Break-in the target Hyper-v.

4. Load the script.
    ```
    hohoho
    ```

5. Execute commands.
    ```
    hohoho
    ```

## References and acknowledgement
- [@ergot86's implementation](https://github.com/ergot86/crap/blob/main/hyperv_stuff.js) as the base of this script.
- [@0vercl0k's an amazing introduction](https://doar-e.github.io/blog/2017/12/01/debugger-data-model/) to Windbg Preview, including authoring extensions.
- [@gerhart_x's IDA Python scripts](https://github.com/gerhart01/Hyper-V-scripts/blob/master/display-vmcs.py) for IDA Pro users (instead of Windbg).
