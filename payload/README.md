# Slime Shady

The payload uses GDI to spawn a few dozens layered / most on top / transparent windows where slimes sprites are animated. It draws on the windows using [Device Independent Bitmaps](https://docs.microsoft.com/en-us/windows/win32/gdi/device-independent-bitmaps). DIBs are basically a palette of RGB colors as well as an array of 1 byte pixels.

![Slime01](sprites/Spin01.png)
![Slime02](sprites/Spin02.png)
![Slime03](sprites/Spin03.png)
![Slime04](sprites/Spin04.png)
![Slime05](sprites/Spin05.png)
![Slime06](sprites/Spin06.png)
![Slime07](sprites/Spin07.png)
![Slime08](sprites/Spin08.png)
![Slime09](sprites/Spin09.png)
![Slime10](sprites/Spin10.png)
![Slime11](sprites/Spin11.png)
![Slime12](sprites/Spin12.png)

There is a master window that receives a message `WM_TIMER` at regular interval and that invalidates every windows' client area. This triggers `WM_PAINT` messages so that every window can update their window.

The [genheaders.py](https://github.com/0vercl0k/CVE-2019-11708/blob/master/payload/src/genheaders.py) Python script preprocesses the [sprites](https://github.com/0vercl0k/CVE-2019-11708/tree/master/payload/sprites) directory and generates a valid compressed set of DIBs that the program will draw using [StretchDIBits](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-stretchdibits).

Thanks to [kaze](http://fat.malcat.fr/) for [inspiration](http://fat.malcat.fr/PayloadBaboons.html) and his blogposts regarding GDI.

## Building the payload

To build the payload, you just have to run `nmake` from a VS 2017 x64 prompt.

```text
CVE-2019-11708\payload>nmake

Microsoft (R) Program Maintenance Utility Version 14.16.27034.0
Copyright (C) Microsoft Corporation.  All rights reserved.

        taskkill /f /im payload.exe
ERROR: The process "payload.exe" not found.
        if not exist .\bin mkdir bin
        python src\genheaders.py sprites
        cl /O1 /nologo /ZI /W3 /D_AMD64_ /DWIN_X64 /sdl /Febin\payload.exe src\payload.cc /link /nologo /debug:full user32.lib
payload.cc
        del *.obj *.pdb *.idb
        if exist .\bin del bin\*.exp bin\*.ilk bin\*.lib
        start .\bin\payload.exe
```

This creates a `payload.exe` / `payload.pdb` file inside the `payload\bin` directory.
