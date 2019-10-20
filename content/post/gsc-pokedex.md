---
title: "Structure And Hacking Of The Pokèdex In Pokèmon Gold, Silver, Crystal"
date: 2019-10-20T00:00:51+02:00
showdate: true
tags:
  - rom-hacking
  - gameboy
  - pokemon
---

Notes on this topic were buried on my hard drive for years now, and rather than making all the work that led to these notes go to waste I am going to share them in the hope that someone finds them useful, even if by today this is all quite outdated thanks to the disassemblies of [Gold](https://github.com/pret/pokegold) and [Crystal](https://github.com/pret/pokecrystal), so this is more like a documentation kind of post, explaining how the Pokèdex data is stored in these games and how to change it manually without having to re-compile the ROM.

**Requirements:**

- A decent hex editor with standard features (goto, search), possibly one designed with ROM hacking in mind in order to import .tbl table files
- An original ROM of either Gold, Silver, Crystal (remember kids, always dump your own ROM's if you want to stay legal!)
- Being familiar with hex editing
- Knowing [how to repoint GameBoy pointers](/post/gb-pointers/)
- Familiarity with the GameBoy's Assembly language is recommended but not mandatory

The choice of the ROM is irrelevant because nothing changes between one or the other except for the addresses in memory of what we are interested in, and I got you covered anyway because I happen to have a list of offsets for every version. For most examples I will be using a ROM of Pokèmon Crystal.

---

## Where is the juice at?

Pokèdex data is just like most data structures in GameBoy games, it's divided in two parts:

- A list of the actual Pokèdex data of each Pokèmon, saved one after the other somewhere in the ROM
- A pointer table pointing at each one of the elements of the list

Pointers and data are saved in different memory locations, not only that, but the list of actual data (not the pointers!) is split in four smaller lists each in a different ROM bank. These are the addresses for Gold and Silver:


| **Data Address** | **Bank Number** | **Base Address** |  **Range**  |
|:--------------:|:-------------:|:--------------:|:---------:|
|    0x1A0000    |      0x68     |    0x1A0000    |   1 - 64  |
|    0x1A4000    |      0x69     |    0x1A4000    |  65 - 128 |
|    0x1A8000    |      0x6A     |    0x1A8000    | 129 - 192 |
|    0x1AC000    |      0x6B     |    0x1AC000    | 193 - 251 |

And these for Crystal:

| **Data Address** | **Bank Number** | **Base Address** |  **Range**  |
|:--------------:|:-------------:|:--------------:|:---------:|
|    0x181695    |      0x60     |    0x180000    |   1 - 64  |
|    0x1B8000    |      0x6E     |    0x1B8000    |  65 - 128 |
|    0x1CC000    |      0x73     |    0x1CC000    | 129 - 192 |
|    0x1D0000    |      0x74     |    0x1D0000    | 193 - 251 |

To see how this data looks like you can use a hex editor, but in order to read the text you also need a table file to correctly encode the in-game text, since different games adopt different text encodings.

You can find a table file (.tbl) for Gold Silver and Crystal on [DataCrystal](https://datacrystal.romhacking.net/wiki/Pok%C3%A9mon_Gold_and_Silver:TBL) and import it on hex editors that support this feature such as [WindHex](https://www.romhacking.net/utilities/291/), [GoldFinger](https://www.romhacking.net/utilities/204/), [HexeCute](https://www.romhacking.net/utilities/206/), and other ones that were developed specifically for ROM hacking.

Here is how the beginning of the Pokèdex data looks like in Gold:

![img](/images/pokedex-gsc/1.png)

And here it is in Crystal:

![img](/images/pokedex-gsc/3.png)

As I said each one of the elements of the list of Pokèdex entries has a pointer telling the game where said entry is in the ROM, so if you need to edit one of the entries and you risk of overflowing into the next one you can repoint the entry's pointer to make it look for the data at a different address, one where you have more space to work with.

Unlike the actual data, pointers are all stored in a single pointer table:

|        **Game**       |    **Offset**   |
|:---------------------:|:---------------:|
|     Gold / Silver     |     0x44360     |
|        Crystal        |     0x44378     |

You can tell you are in a pointer table when you notice a pattern like this (picture from the ROM of Gold):

![img](/images/pokedex-gsc/2.png)

In Crystal the pointers are different but the pattern is pretty much the same:

![img](/images/pokedex-gsc/4.png)

The second byte of every 2-bytes long pointer repeats itself a couple times before being incremented, while the first changes every time.

You can easily calculate the location in memory of your desired Pokèmon's Pokèdex entry pointer from its Pokèdex number with the formula:

|        **Game**       |    **Formula**    |
|:---------------------:|:-----------------:|
|     Gold / Silver     | 0x4435E + (2 * N) |
|        Crystal        | 0x44376 + (2 * N) |

Where *N* is of course the Pokèdex number of your interest.

---

## A couple unnecessary thoughts

This section is absolutely optional, here I just show some ASM code and talk a bit about the complications of wanting to expand the Pokèdex by big numbers, so if you're only interested in the data structure of Pokèdex entries you can skip this part altogether.

Now let's assume you wanted to move some of this Pokèdex data somewhere else, in another bank. Or perhaps you want to add a fifth bank because you are adding more Pokèmon to the game and so you want all of them to have their own Pokèdex entries, you're soon going to run out of free space in the fourth dedicated bank the developers originally dedicated to Pokèdex entries.

How would you tell the game where to look for the data now that it's not in the original location anymore? Let's investigate.

The Assembly routines responsible for calculating the pointer of a Pokèmon's Pokèdex data is at 0x44326 for G/S and 0x44333 for Crystal, here is the latter, heavily commented to make it comprehensible for those not too familiar with ASM:

```gameboy
#org 44333
E5			push hl			; save HL on the stack
21 78 42	ld hl,4378		; load the address of the pokèdex data pointer table into HL
78			ld a,b			; A = B = number of the pokèmon we're interested in
3D			dec a			; A--, the pokèdex counts from 1 but tables start from 0
16 00		ld d,00			; D = 0, it prepares it for the following 16 bits addition so that it doesn't influence the result
5F			ld e,a			; E = A
19			add hl,de		; HL = (baseOffset + index)
19			add hl,de		; because pointers are two bytes long the addition is done twice, and the correct address is found
5E			ld e,(hl)		; E = first byte of the pointer
23			inc hl			; increment HL to access the second byte
56			ld d,(hl)		; which is then loaded into D
D5			push de			; save DE on the stack so that the registers can be used for the next calculations too
07			rlca			; rotate A to the left
07			rlca			; do it once more
E6 03		and a,03		; A = A & 3, this is used to obtain the index value for the list of banks
21 51 43	ld hl,4351		; load the list of ROM banks in HL
16 00		ld d,00			; once again D is initialized for the 16 bits addition
5F			ld e,a			; E now contains the result of the logical operation
19			add hl,de		; and it's used as index for the list of banks to obtain the address of the correct bank, which is stored into HL
46			ld b,(hl)		; and then the bank number itself is placed into B
D1			pop de			; the value of the pointer calculated previously is also retrieved from the stack and placed into DE
E1			pop hl			; retrieve the last value from the stack
C9			ret				; return to callee
```

For Gold and Silver the routine is very similar although not identical:

```gameboy
#org 44326
E5			push hl			; save HL on the stack
21 60 43	ld hl,4360		; load the address of the pokèdex data pointer table into HL
78			ld a,b			; B = A = number of the pokèmon we're interested in
3D			dec a			; A--, the pokèdex counts from 1 but tables start from 0
16 00		ld d,00			; D = 0, it prepares it for the following 16 bits addition so that it doesn't influence the result
5F			ld e,a			; E = A
19			add hl,de		; HL = (baseOffset + index)
19			add hl,de		; because pointers are two bytes long the addition is done twice, and the correct address is found
5E			ld e,(hl)		; E = first byte of the pointer
23			inc hl			; increment HL to access the second byte
56			ld d,(hl)		; which is then loaded into D
07			rlca			; rotate A to the left
07			rlca			; do it once more
E6 03		and a,03		; A = A & 3, this is used to obtain the index value for the list of banks
C6 68		add a,68		; add the number of the first bank containing the pokèdex data to the result of the previous operation, the result is the correct bank number
47			ld b,a			; which is saved into B
E1			pop hl			; the stack is restored to its previous state
C9			ret				; and the routine ends
```

Both routines return a value like this: B:DE, where B is the bank number and DE contains the 2 bytes long pointer that contains an address relative to a bank, these two together make an absolute address:

```aaa
dataAddress = (bankNumber * 0x4000) + ([reversedPointer] - 0x4000)
```

Unlike in Crystal, the four ROM banks containing Pokèdex data are one after the other in Gold and Silver, so the developers hardcded the first bank number in the ASM routine and used a simple addition:

```gameboy
rlca
rlca
and a,03
add a,68
```

In Crystal however the pokèdex banks aren't contiguous, so the approach was slightly different: the banks containing pokèdex data are saved into an array, which we find just after the end of the routine:

![img](/images/pokedex-gsc/6.png)

Followed by the callee of the routine we have just examined:

```gameboy
#org 44355
CD 33 43	call $4333		; call the routine above to obtain the address of the pokèdex data
```

I'm not going to show the rest of this function because there are a couple details I'm not so sure of, so instead of leaving information blank I'm not showing it altogether, the address is there though so if you want to give it a look yourself go ahead.

Anyway, I am pointing this out because while reading the code for the first function I noticed that the logical operation effectively hardcodes the number of banks inside which the data is distributed:

```gameboy
E6 03		and a,03
```

This means one would need to rewrite this function if they were to add more Pokèdex entries than the last officially used bank allows for, and there is no free room after this function, it goes straight to the bank numbers and then to the next function, so repointing would be needed, the repointing would have to take place at 0x44356 to be exact, equivalent to the first byte of the green rectangle in the below picture:

![img](/images/pokedex-gsc/7.png)

Luckily the 17th bank (0x11), the one where all this code is in, has a lot of empty space at the bottom so repointing should be easy if you write your new Assembly routine there:

![img](/images/pokedex-gsc/8.png)

You have 934 available free bytes in this bank, it's way more than you need for a single routine.

*Small note: maybe changing that instruction to "and a,numberOfBanks" and repointing the array of banks somewhere else to add more entries to it is really all one needs to do as first step to expand the Pokèdex? I might look more into this, however this can only be achieved on Crystal, because the routine in Gold assumes all entries are stored in contiguous banks, and the ones after the fourth bank are already occupied. Luckily, the disassembly of Pokèmon Gold seems to have adopted Crystal's approach as well, using an array instead of a simple addition*

This is not everything you would need to do in order to add a fifth bank of Pokèdex entries, looking at the disassembly I spotted lines like this:

```gameboy
ld bc, wPokedexDataEnd - wPokedexDataStart
```

That wPokedexDataEnd is of course a variable somewhere in the ROM that needs to be changed, and this is just one, the full code handling the Pokèdex is quite long so I didn't bother going through the whole thing to identify what would need to be changed (since it never was the scope of this post), but I thought it would be fair to mention it in case anyone reading this was interested in adding *a lot* of new Pokèmon in their hack. If you want to see the code it's [here](https://github.com/pret/pokecrystal/tree/master/engine/pokedex).

If anybody has done it, I would be very interested to see how they did it.

---

## Data structure

After all that rambling let's take a close look at how the game stores the data we needed so much time to locate:

```c
typedef struct dexEntry {
	char name[];
	uint16_t height;
	uint16_t weight;
	char description[];
} pokedexEntry;
```

As usual let's take Bulbasaur as an example to see the data structure with a hex editor:

![img](/images/pokedex-gsc/9.png)

**Name, description:**

*name* and *description* can have various sizes as long as a few rules are respected:

- *name* isn't actually the Pokèmon's name, it's the Pokèmon's species, for example Bulbasaur is the SEED Pokèmon;
- *name* can only hold up to 10 characters, it requires a trailing 0x50 string terminator byte (example: Squirtle --> TINYTURTLE[0x50])
- *description* has to be split in two different pages, each of up to 51 characters including line breaks
- every page can only have up to three lines
- a single line in *description* can be up to 18 bytes long, including line breaks

For the *description* field you also have to keep in mind you have to write text following the game's own encoding, so make sure you have loaded the correct .tbl file and that you are in text editing mode when doing this.

In addition you have to use these two special characters:

- 0x4E = line break 
- 0x50 = terminate names, end page

For example the original description of Bulbasaur in Pokèmon Crystal is formatted as follows:

```aaa
While it is young,[0x4E]
it uses the[0x4E]
nutrients that are[0x50]
stored in the[0x4E]
seeds on its back[0x4E]
in order to grow.[0x50]
```

**Height, weight:**

This is the only part that is going to be a little confusing, the way height and weight are stored isn't the most intuitive. Here's how to retrieve the original values from the 16 bits values taken from the ROM:

1. Flip the two bytes (the GameBoy's CPU follows the little endian standard)
+ Convert the 16 bits value to base 10 as a whole
+ If calculating height, count the last two digits as decimal. If calculating weight, count only the very last

Let's try to get Onix's height back:

```aaa
1) FA 0A
2) 0A FA
3) 0AFA
4) 2810
---------
5) 28.10
```

And for its weight:

```aaa
1) 16 12
2) 12 16
3) 1216
4) 4630
---------
5) 463.0
```

We can confirm the calculations are correct:

![img](/images/pokedex-gsc/10.png)

Let's make a test going the other way, starting from a new arbitrary value for both height and weight to overwrite the originals.

Suppose we want to give Onix a height of 6.66 and a weight of 133.7, remembering that height must always have two decimal digits and weight only one:

```aaa
1) 6.66
2) 666
3) 029A
4) 02 9A
---------
5) 9A 02
```

And for the weight:

```aaa
1) 133.7
2) 1337
3) 0539
4) 05 39
---------
5) 39 05
```

Let's see if the values are correct:

![img](/images/pokedex-gsc/11.png)

---

And with this the post is over. I might make a part two where I actually go into detail on how to expand the Pokèdex directly from the ROM and then maybe from the disassembly too, but it's going to require time, a lot of time, mainly because I have never tried it before and so I will need a lot of research and testing to do.

If I do end up making more research on this topic you'll see a link pointing to part two, but for now I'll keep focusing on dumping old personal notes and expanding on those.

Thank you for reading this far!



