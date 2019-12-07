# Axel '0vercl0k' Souchet - November 29 2019
import sys
import os
import ctypes
from PIL import Image

def tabs(n):
    '''Get enough space for `n` tabs.'''
    return '    ' * n

def write_array(fout, arr, ntabs = 1):
    '''Format an uint8_t array in the output file.''' 
    fout.write('{')
    for i, by in enumerate(arr):
        if (i % 8) == 0:
            fout.write('\n' + tabs(ntabs))
        fout.write('0x%.2x, ' % by)
    fout.write('''
%s}''' % tabs(ntabs - 1))

def palette2win(palette):
    '''Convert a color palette into a palette that is friendly for Windows.
    `RGBQUAD` on Windows order blue, green, red, so we reorder here..
    We also append a zero byte for the `reserved` field in each `RGBQUAD`.
    typedef struct tagRGBQUAD {
            BYTE    rgbBlue;
            BYTE    rgbGreen;
            BYTE    rgbRed;
            BYTE    rgbReserved;
    } RGBQUAD;'''
    win_palette = []
    for i in range(0, len(palette), 3):
        r, g, b = palette[i : i + 3]
        win_palette.extend([b, g, r, 0])

    assert len(win_palette) == (256 * 4), 'Palette is expected to have 256 RGQUAD.'
    return win_palette

def getbackground_color(im):
    '''Get the background RGB components. The most used color is assumed to be the
    background color.'''
    # Get the most used color, we'll assume it is the background.
    _, background_color = im.getcolors()[-1]
    palette = im.getpalette()
    # Get the RGB components off the palette.
    r, g, b = palette[background_color * 3 : (background_color * 3) + 3]
    return (r, g, b)

def compress(buffer_in, fmt):
    '''Compress a buffer with a specific format.'''
    COMPRESSION_ENGINE_MAXIMUM = 256
    RtlCompressBuffer = ctypes.windll.ntdll.RtlCompressBuffer
    RtlGetCompressionWorkSpaceSize = ctypes.windll.ntdll.RtlGetCompressionWorkSpaceSize

    fmt_engine = fmt | COMPRESSION_ENGINE_MAXIMUM
    workspace_size = ctypes.c_ulong(0)
    workspace_fragment_size = ctypes.c_ulong(0)
    res = RtlGetCompressionWorkSpaceSize(
        ctypes.c_ushort(fmt_engine),
        ctypes.pointer(workspace_size),
        ctypes.pointer(workspace_fragment_size)
    )

    assert res == 0, 'RtlGetCompressionWorkSpaceSize failed.'

    workspace = ctypes.c_buffer(workspace_size.value)
    buffer_out = ctypes.c_buffer(len(buffer_in))
    compressed_size = ctypes.c_ulong(0)
    res = RtlCompressBuffer(
        ctypes.c_ushort(fmt_engine),
        buffer_in,
        len(buffer_in),
        buffer_out,
        len(buffer_out),
        ctypes.c_ulong(4096),
        ctypes.pointer(compressed_size),
        workspace
    )

    assert res == 0, 'RtlCompressBuffer failed.'
    return buffer_out.raw[: compressed_size.value]

def compress_sprites(sprites):
    '''Find the best compression ratio for the set of `sprites`.'''
    compression_formats = {
        2 : 'COMPRESSION_FORMAT_LZNT1',
        3 : 'COMPRESSION_FORMAT_XPRESS',
        4 : 'COMPRESSION_FORMAT_XPRESS_HUFF'
    }

    sprites_buffer = []
    for sprite in sprites:
        sprites_buffer.extend(sprite.getdata())

    sprites_buffer = ''.join(map(chr, sprites_buffer))
    bestformat, bestcompressed = '', None
    for compression_format in compression_formats.keys():
        compressed_buffer = compress(sprites_buffer, compression_format)
        if bestcompressed is None or len(compressed_buffer) < len(bestcompressed):
            bestformat = compression_formats[compression_format]
            bestcompressed = compressed_buffer

    return (bestformat, map(ord, bestcompressed), len(sprites_buffer))

def main(argc, argv):
    if argc != 2:
        print './genheaders.py <folder png file>'
        return 0

    sprites_dir = argv[1]
    sprites = []
    assert os.path.isdir(sprites_dir), 'The first argument should be a directory.'

    for filename in os.listdir(sprites_dir):
        if not filename.endswith('.png'):
            continue

        path = os.path.join(sprites_dir, filename)
        im = Image.open(path)
        im = im.convert('P')
        w, h = im.size
        # According to the doc we need aligned scan lines, so resize until it works:
        # The scan lines must be aligned on a DWORD except for RLE-compressed bitmaps.
        while (w % 4) != 0:
            w *= 2
            h *= 2
        im = im.resize((w, h))
        sprites.append(im)

    assert all(im.size == sprites[0].size for im in sprites), 'The sprites are expected to be the same size.'
    assert all(im.getpalette() == sprites[0].getpalette() for im in sprites), 'The palettes are expected to be the same.'
    assert not all(list(im.getdata()) == list(sprites[0].getdata()) for im in sprites), 'The sprites are supposed to be different.'
    assert all(getbackground_color(im) == getbackground_color(sprites[0]) for im in sprites), 'The transparent color is expected to be the same.'

    with open(os.path.join('src', 'sprites.h'), 'w') as fout:
        fmt, compressed_sprites, decompressed_size = compress_sprites(sprites)
        w, h = sprites[0].size
        r, g, b = getbackground_color(sprites[0])
        fout.write('''#pragma once
#include <cstdint>
#include <windows.h>

const uint32_t kSpriteWidth = %d;
const uint32_t kSpriteHeight = %d;
const uint32_t kSpriteSize = %d;
const COLORREF kTransparentColor = RGB(%d, %d, %d);

const size_t kUncompressedSize = %d;
const size_t kNumberOfSprites = %d;
const uint16_t kCompressionFormat = %s;

struct Sprite_t {
    uint8_t Bytes[kSpriteSize];
};

const uint8_t kPalette[256 * sizeof(RGBQUAD)] = ''' % (
            w, h, w*h, r, g, b, decompressed_size, len(sprites), fmt
        ))
        write_array(fout, palette2win(sprites[0].getpalette()))
        fout.write(''';

const uint8_t kCompressedSprites[] = ''')

        write_array(fout, compressed_sprites)
        fout.write(';')
    return 1

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)
