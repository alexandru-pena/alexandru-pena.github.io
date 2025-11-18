---
layout: default
---

<a href="./WinAntiDbg0x300.zip" id="download-zip" class="button"><span>Download .zip</span></a><br><br>

## WinAntiDbg0x300



**Description**

This challenge is a little bit invasive. It will try to fight your debugger. With that in mind, debug the binary and get the flag!
This challenge executable is a GUI application and it requires admin privileges. And remember, the flag might get corrupted if you mess up the process's state.


**Write-up**
- Disabled debugging mechanisms.
    - NtQueryInformationProcess
    - IsDebuggerPresent
![alt text](image-1.png)

- Patched binary 
    - Function at address 0x00403050 jumped over flag printing block


**Solution**
```javascript
var addr_isDebuggerPresent = Process.getModuleByName("kernel32.dll").findExportByName("IsDebuggerPresent");
var addr_NtQueryInformationProcess = Process.getModuleByName("ntdll.dll").findExportByName("NtQueryInformationProcess");
var addr_DebugActiveProcess = Process.getModuleByName("kernel32.dll").findExportByName("DebugActiveProcess");
var addr_OutputDebugStringW = Process.getModuleByName("kernel32.dll").findExportByName("OutputDebugStringW");
var func_debugActive = new NativeFunction(addr_DebugActiveProcess, 'bool', ['uint32']);
var addr_CreateProcessA = Process.getModuleByName("kernel32.dll").findExportByName("CreateProcessA");

// Attempt hooks to main memory map
var addr_windbgexe = Process.getModuleByName("patched_unpacked-winantidbg0x300.exe").base;

// ghidra offsets
var ghidra_base = 0x00400000;
var ghidra_offset_decrypt_function = 0x00402bc0;
var ghidra_offset_flag_ptr = 0x0040c3d0;
var ghidra_offset_some_conditions_func = 0x00403050;

// real offsets
var decrypt_func_offset = ghidra_offset_decrypt_function - ghidra_base;
var ptr_flag_offset = ghidra_offset_flag_ptr - ghidra_base;
var some_conditions_func = ghidra_offset_some_conditions_func - ghidra_base;

// Pointer to function
var addr_func_decrypt = addr_windbgexe.add(decrypt_func_offset);
var addr_some_conditions = addr_windbgexe.add(some_conditions_func);

// Pointer to data section
var ptr_flag = addr_windbgexe.add(ptr_flag_offset);


// Silly me attempting to read the flag...
Interceptor.attach(addr_func_decrypt, {
    onEnter(args) {
        //console.log("Entering decrypt function.");
    },
    onLeave(ret) {
        console.log("After this decrypt round the flag is: " + ptr_flag.readUtf16String());
    }
});


Interceptor.attach(addr_some_conditions, {
    onEnter(args) {
        console.log("Interesting.... hummm....");
    },
    onLeave(ret) {
        console.log("even more interesting.... hummm....");
    }
});


// **************** Generic Interceptors to disable debugging mechanisms... ****************

Interceptor.attach(addr_CreateProcessA, {
    onEnter(args) {
        console.log("ok im trying to create a process...");
    }
});



Interceptor.attach(addr_OutputDebugStringW, {
    onEnter(args) {
        console.log("DEBUG MESSAGE: " + args[0].readUtf16String());
    }
});


Interceptor.attach(addr_isDebuggerPresent, {
    onEnter(args) {
        //console.log("IsDebuggerPresent called.");
    },
    onLeave(retval) {
        retval.replace(ptr(0));
        console.log("IsDebuggerPresent - replaced to 0");
    }
});

Interceptor.attach(addr_NtQueryInformationProcess, {
    onEnter(args) {
/*         __kernel_entry NTSTATUS NtQueryInformationProcess(
            [in]            HANDLE           ProcessHandle,
            [in]            PROCESSINFOCLASS ProcessInformationClass,
            [out]           PVOID            ProcessInformation,
            [in]            ULONG            ProcessInformationLength,
            [out, optional] PULONG           ReturnLength
        ); */
        var originalPic = args[1].toInt32();

        if(originalPic == 31) {
            args[1] = ptr(26);
            console.log("NtQueryInformationProcess called — ProcessInformationClass =", args[1].toInt32());
        } 
    },
    onLeave(status) {
/*         if(this.informationId == 27) {
            var len = this.ProcessInformation.add(0).readUShort();
            var content = this.ProcessInformation.add(8).readUtf16String(len);

            console.log("Type ID 27. Reading len: " + len + ", content: " + content);
        }
        else if(this.informationId == 31) {
            var content = this.ProcessInformation.readULong();
            console.log("Type ID 31. content: " + content);

            var newPtr = Memory.alloc(4);
            newPtr.writeS32(0);

            this.ProcessInformation = newPtr;
            content = this.ProcessInformation.readULong();
            console.log("REPLACED Type ID 31. content: " + content);
        } */
    }
});
```

![alt text](image.png)


Flag: picoCTF{Wind0ws_antid3bg_0x300_86fcf897}


[back](./../..)
