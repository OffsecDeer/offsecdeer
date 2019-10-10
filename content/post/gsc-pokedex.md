---
title: "Structure And Hacking Of The Pokèdex In GameBoy Color Games"
date: 2019-10-10T00:09:05+02:00
toc: true
showdate: true
tags:
  - rom-hacking
  - gameboy
  - pokemon
draft: true
---

Notes on this topic were buried on my hard drive for years now, and rather than making all the work that led to these notes go to waste I am going to share them in the hope that someone finds them useful, even if by today this is all quite outdated thanks to the disassemblies of [Gold](https://github.com/pret/pokegold) and [Crystal](https://github.com/pret/pokecrystal), so this is more like a documentation kind of post, explaining how the Pokèdex data is stored in these games and how to change it manually without having to deal with Z80 ASM and re-compile the ROM.

**Requirements:**

- A decent hex editor with standard features (goto, search)
- An original ROM of either Gold, Silver, Crystal
- Being familiar with hex editing
- Knowing [how to repoint GameBoy pointers](/post/gb-pointers/)
- A bit of patience to get through this post

The choice of the ROM is irrelevant because nothing changes between one or the other except for the addresses in memory of what we are interested in, and I got you covered anyway because I happen to have a list of offsets for every version. For most examples I will be using a ROM of Pokèmon Crystal.

---

## Where is the juice at?

Pokèdex data is just like most data structures in GameBoy games, it's divided in two parts:

- A list of the actual Pokèdex data of each Pokèmon, saved one after the other somewhere in the ROM
- A pointer table pointing at each one of the elements of the list

Pointers and data are saved in different memory locations, not only that, but the list is split in four smaller lists each in a different ROM bank. These are the addresses for Gold and Silver:


| *Data Address* | *Bank Number* | *Base Address* |  *Range*  |
|:--------------:|:-------------:|:--------------:|:---------:|
|    0x1A0000    |      0x68     |    0x1A0000    |   1 - 64  |
|    0x1A4000    |      0x69     |    0x1A4000    |  65 - 128 |
|    0x1A8000    |      0x6A     |    0x1A8000    | 129 - 192 |
|    0x1AC000    |      0x6B     |    0x1AC000    | 193 - 251 |

And these for Crystal:

| *Data Address* | *Bank Number* | *Base Address* |  *Range*  |
|:--------------:|:-------------:|:--------------:|:---------:|
|    0x181695    |      0x60     |    0x180000    |   1 - 64  |
|    0x1B8000    |      0x6E     |    0x1B8000    |  65 - 128 |
|    0x1CC000    |      0x73     |    0x1CC000    | 129 - 192 |
|    0x1D0000    |      0x74     |    0x1D0000    | 193 - 251 |

To see how this data looks like you can use a hex editor, but in order to read the text you also need a table file to correctly encode the in-game text, since different games adopt different text encodings.

You can find a table file (.tbl) for Gold Silver and Crystal on [DataCrystal](https://datacrystal.romhacking.net/wiki/Pok%C3%A9mon_Gold_and_Silver:TBL) and import it on hex editors that support this feature such as [WindHex](https://www.romhacking.net/utilities/291/), [GoldFinger](https://www.romhacking.net/utilities/204/), [HexeCute](https://www.romhacking.net/utilities/206/), and other ones that were made with ROM hacking in mind.

Here is how the beginning of the Poèdex data looks like in Gold:

![img](/images/pokedex-gsc/1.png)

And here it is in Crystal:

![img](/images/pokedex-gsc/3.png)

As I said each one of the elements of the list of Pokèdex entries has a pointer telling the game where said entry is in the ROM, so if you need to edit one of the entries and you risk of overflowing into the next one you can repoint the entry's pointer to make it look for the data at a different address, one where you have more space to work with.

Unlike the actual data, pointers are all stored in a single pointer table:

```aaa
Gold / Silver: 0x44360
Crystal: 0x44378
```

You can tell you are in a pointer table when you notice a pattern like this (picture from the ROM of Gold):

![img](/images/pokedex-gsc/2.png)

In Crystal the pointers are different but the pattern is pretty much the same:

![img](/images/pokedex-gsc/4.png)

The second byte of every 2-bytes long pointer repeats itself a couple times before being incremented, while the first changes every time.

You can easily calculate the location in memory of your desired Pokèmon's Pokèdex entry pointer from its Pokèdex number with the formula:

```aaa
G/S:
0x4435E + (2 * N)

C:
0x44376 + (2 * N)
```

Where *N* is of course the Pokèdex number of your interest.

The Assembly routine responsible for calculating the pointer of a Pokèmon's data is at 0x for G/S and 0x44333 for Crystal:

```aaa
#org 44333
E5			push hl
21 78 42	ld hl,4378
78			ld a,b
3D			dec a
16 00		ld d,00
5F			ld e,a
19			add hl,de
19			add hl,de
5E			ld e,(hl)
23			inc hl
56			ld d,(hl)
D5			push de
07			rlca
07			rlca
E6 03		and a,03
21 51 43	ld hl,4351
16 00		ld d,00
5F			ld e,a
19			add hl,de
46			ld b,(hl)
D1			pop de
E1			pop hl
C9			ret
```

Just below that we find the definition of the four ROM banks at addresses :

![img](/images/pokedex-gsc/6.png)

Followed by the callee of the routine we saw above :

```aaa
#org 44355
CD 33 43	call $4333
E5			push hl
62			ld h,d
6B			ld l,e
78			ld a,b
CD 4D 30	call $304D
23			inc hl
FE 50		cp a,$50
20 F7		jr nz,$435B
23			inc hl
23			inc hl
23			inc hl
23			inc hl
0D			dec c
28 09		jr z,$4374
78			ld a,b
CD 4D 30	call $304D
23			inc hl
FE 50		cp a,$50
20 F7		jr nz,$436B
54			ld d,h
5D			ld e,l
E1			pop hl
C9			ret
```

This function is used to find a pointer to the first page of a Pokèdex entry, and in order to do so it needs the pointer to the general entry first and then iterate through the data that it has to ignore (see below for the entry data structure), in fact that first instruction, *call $4333* is the callee of the function we saw earlier.

I am pointing this out because while reading the code for the first function I noticed that the number of ROM banks in which the list of Pokèmon is distributed is hardcoded:

```aaa
E6 03		and a,03
```

Which on the disassembly for Crystal becomes:

```aaa
maskbits NUM_DEX_ENTRY_BANKS
```

This means one would need to rewrite this function if they were to add more Pokèdex entries than the last officially used bank allows for, and there is no free room after this function, it goes straight to the bank numbers and then to the next function, so repointing would be needed, the repointing would have to take place at 0x44356 to be exact, equivalent to the first byte of the green rectangle in the below picture:

![img](/images/pokedex-gsc/7.png)

Luckily the 11th bank, the one where all this code is in, has a lot of empty space at the bottom so repointing should be easy if you write your new Assembly routine there:

![img](/images/pokedex-gsc/8.png)

You have 934 available free bytes in this bank, it's way more than you need for a single routine.

This is not everything you would need to do in order to add a fifth bank of Pokèdex entries, looking at the disassembly I spotted lines like these:

```aaa
ld bc, wPokedexDataEnd - wPokedexDataStart
```

That wPokedexDataEnd is of course a variable somewhere in the ROM that needs to be changed, and this is just one, the full code handling the Pokèdex is quite long so I didn't bother going through the whole thing to identify what would need to be change (since it never was the scope of this post), but I thought it would be fair to mention it in case anyone reading this was interested in adding *a lot* of new Pokèmon in their hack. If you want to see the code it's [here](https://github.com/pret/pokecrystal/tree/master/engine/pokedex).

If anybody has done it, I would be very interested to see how they did it.

---

## Data structure

After all that rambling let's take a close look at how the game stores the data we needed so much time to locate:

```c
#define STRING_TERMINATOR uint8_t terminator = 0x50;

typedef struct dexEntry {
	char name[];
	STRING_TERMINATOR
	uint16_t height;
	uint16_t weight;
	char description[];
	STRING_TERMINATOR
} pokedexEntry;
```

*name* and *description* can have various sizes as long as a few rules are respected:

- *name* isn't actually the Pokèmon's name, it's the Pokèmon's species, for example Bulbasaur is the SEED Pokèmon;
- *name* can only hold up to 10 characters, it requires a trailing 0x50 string terminator byte (example: Squirtle --> TINYTURTLE[0x50])






















 