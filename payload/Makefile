# Axel '0vercl0k' Souchet - November 24 2019
TARGET = payload.exe

SOURCES = \
    src\payload.cc \

CFLAGS = /O1 /nologo /ZI /W3 /D_AMD64_ /DWIN_X64 /sdl
LDFLAGS = /nologo /debug:full user32.lib

all: kill $(TARGET) clean launch

$(TARGET): $(SOURCES)
    if not exist .\bin mkdir bin
    python src\genheaders.py sprites
    cl $(CFLAGS) /Febin\$@ $** /link $(LDFLAGS)

kill:
# The character '-' is used to ignore the return value of `taskkill`.
# If we don't do that, if the target is not running, `taskkill` returns an
# error and the Makefile stops.
    -taskkill /f /im $(TARGET)

launch: kill
    start .\bin\$(TARGET)

clean:
    del *.obj *.pdb *.idb
    if exist .\bin del bin\*.exp bin\*.ilk bin\*.lib
