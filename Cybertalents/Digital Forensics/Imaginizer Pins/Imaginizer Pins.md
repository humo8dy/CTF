# Imaginizer Pins — Reverse-Engineering Write-Up

## Challenge overview

**Challenge:** Imaginizer Pins  
**Input:** `Imaginizer.exe`  
**Goal:** Recover the hidden 32-character hexadecimal key from an application that works with user-supplied images.

I approached this as a .NET reverse-engineering task. The important part was not to guess the key from the visible strings. I first identified the executable's protection, then followed its protected string-loading path until I could recover the decompressed string table.

> **Flag handling:** I intentionally do not include the recovered value anywhere in this write-up. The helper script prints it only when run locally.

## Tools

- `file`, `strings`, and `objdump` for initial PE inspection.
- **dnSpyEx** or another .NET debugger/decompiler for inspecting the managed assembly and its protected initialization code.
- Python 3.8+ for the final LZMA and string-table parsing step. The helper uses only Python's standard library.

## 1. Identify the executable

I started by checking the file type and calculating its SHA-256 hash:

```bash
file Imaginizer.exe
sha256sum Imaginizer.exe
```

The file is a 32-bit Windows PE executable containing a Mono/.NET assembly. Its SHA-256 hash is:

```text
32e2552bb94dd11ba440308bc46fce8d1ad5bde33e4c417d648d7165f48395fd
```

I then inspected the PE sections:

```bash
objdump -h Imaginizer.exe
```

The first section has an unusual, non-standard name, while the remaining sections include `.text`, `.rsrc`, and `.reloc`. This is a useful early clue that the executable has been packed or protected.

I also checked the PE headers:

```bash
objdump -p Imaginizer.exe
```

The headers contain a CLR Runtime Header, confirming that the file is a managed .NET executable rather than a normal native Windows program.

## 2. Recognize the obfuscation

A quick strings pass does not reveal the important application strings:

```bash
strings -a Imaginizer.exe
```

The result contains mostly unreadable data. Looking more closely at the managed metadata reveals several signs of obfuscation:

- The assembly contains a `ConfusedByAttribute` marker, which is consistent with ConfuserEx-protected .NET assemblies.
- The metadata string heap contains long identifiers made from invisible Unicode directional-control characters. These characters can make names look blank or misleading in ordinary tools.
- The module initializer (`.cctor`) and the protected first section are important because the protection code uses initialization-time logic to restore code that is not directly readable on disk.

At this point, searching the raw executable for a flag-shaped string is not enough. The relevant data is transformed before it becomes a normal string table.

## 3. Inspect and recover the protected code

I opened the assembly in dnSpyEx and inspected the module initializer and the protected methods. The goal was to follow the anti-tamper initialization path rather than to execute the image-generation workflow blindly.

The protection routine restores method data at runtime. After recovering the protected method bodies, I followed the string-loading routine until it reached its LZMA decompression step.

The key point in this stage is that the decoder receives a compact binary buffer. That buffer is the input for the helper script in this repository.

### Dump the LZMA input buffer

Using the debugger, locate the LZMA decoding call inside the recovered string-loader path. Dump the complete input buffer passed to the decoder and save it as:

```text
lzma_input.bin
```

For this challenge, the buffer is **320 bytes** long. Its first 13 bytes form an LZMA-Alone-style header:

```text
5D 00 00 80 00 54 01 00 00 00 00 00 00
```

The header gives the decoder properties, dictionary size, and uncompressed size. The declared output size is `0x154` bytes, or **340 bytes**.

The compressed stream is zero-padded and does not contain a normal end-of-stream marker. That is why the helper uses the raw LZMA1 decoder with the output size from the header instead of relying on a regular one-line `lzma.decompress()` call.

## 4. Decompress and parse the string table

I included the final extraction step in [`extract_key.py`](extract_key.py). It does two things:

1. Reads the LZMA header, configures the raw LZMA1 decoder, and checks that the output is exactly 340 bytes.
2. Parses the decompressed data as a sequence of UTF-8 strings. Each entry has a four-byte little-endian length field, followed by the string bytes. Entries are aligned to four-byte boundaries.

Run it with:

```bash
python extract_key.py lzma_input.bin
```

The script searches the parsed entries for a unique value containing exactly 32 lowercase hexadecimal characters. It prints the recovered value to the terminal. The value is intentionally omitted from this document.

If the decompressed 340-byte table has already been saved, the script can parse it directly:

```bash
python extract_key.py decoded_strings.bin --raw-table
```

No third-party Python packages are required.

## 5. Connect the result to the image functionality

The managed metadata also reveals the image-processing APIs used by the application, including:

- `Bitmap` and `Image` for loading and manipulating images.
- `GetPixel` and `SetPixel` for reading and writing individual pixels.
- `Color.FromArgb` and the red, green, and blue channel accessors for working with pixel colour values.
- `Random.Next` and `DateTime.Now.Second`, which indicate that the image routine also uses generated or time-dependent values.

The application contains user-facing strings referring to a minimum image width and height of 1000 pixels, an output file named `generated.bmp`, and a completion message. These references connect the recovered data to the image-processing part of the program.

The decisive finding is that the decompressed string table itself contains a single 32-character lowercase hexadecimal entry. I did not need to guess the value from an image or search the executable's ordinary ASCII strings; I recovered it from the protected string-loading path.

## 6. Result

The challenge value is a 32-character lowercase hexadecimal string. I have deliberately redacted it from this GitHub write-up, terminal transcripts, and screenshots.

To reproduce the final extraction, dump the 320-byte LZMA input buffer as described in Step 3 and run `extract_key.py` as shown in Step 4.

I recommend keeping the original challenge executable and any memory dumps out of a public repository unless the challenge rules explicitly allow redistribution. The helper script contains no hard-coded challenge key.


