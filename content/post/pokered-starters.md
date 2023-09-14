---
title: "Pokémon Red Disassembly: Modifying The Starters"
date: 2023-09-14T00:00:01+02:00
showdate: true
tags:
  - rom-hacking
  - gameboy
  - pokemon
---

This is a guide I originally wrote back in 2015 for an Italian Pokémon ROM hacking forum because nobody else had done so already, I thought I would translate and archive it here too since this site is meant to be a place for me to backup my work, old or new, I hope it can be useful even for just one curious soul who ever asked themselves: how can you change the three starters in pokered? Well, here is how.

**CONSTANTS**

First we need to modify the STARTER constants: `STARTER1`, `STARTER2`, `STARTER3`. When I first wrote my guide these were defined in constants/starter_mons.asm but this file has since been deleted and the constants are now found in [constants/pokemon_constants.asm](https://github.com/pret/pokered/blob/master/constants/pokemon_constants.asm#L203):
```text
; starters
DEF STARTER1 EQU CHARMANDER
DEF STARTER2 EQU SQUIRTLE
DEF STARTER3 EQU BULBASAUR
```

If you have an older pokered version still using starter_mons.asm, this is what it should look like:
```text
STARTER1 EQU CHARMANDER
STARTER2 EQU SQUIRTLE
STARTER3 EQU BULBASAUR
```

Replace the default names with the ones of your choice, regardless of what version you are using a complete list of all pokémon constant names is found in constants/pokemon_constants.asm if you need them for reference.

**DIALOG**

Next up is Professor Oak's dialog shown when you have chosen your starter, this is found in text/OaksLab.asm in new disassembly versions and in text/maps/oaks_lab.asm in older ones, this is what the structure looks like (all that changes between versions is the name of the dialog options):
```text
_OaksLabYouWantCharmanderText::
	text "So! You want the"
	line "fire #MON,"
	cont "CHARMANDER?"
	done

_OaksLabYouWantSquirtleText::
	text "So! You want the"
	line "water #MON,"
	cont "SQUIRTLE?"
	done

_OaksLabYouWantBulbasaurText::
	text "So! You want the"
	line "plant #MON,"
	cont "BULBASAUR?"
	done
```

Dialog to be shown in game is formatted with custom macros:
- `text` begin the dialog
- `line` write on the second line of the dialog box
- `cont` scroll down and write on the first line
- `done` end of dialog, wait for button press

Keep in mind only two lines of text can be shown at once in the dialog box, also "#MON" is a special string that is replaced by "POKEMON" when the dialog is actually shown in game.

**RIVAL TEAM**

Your rival's team changes based on what pokémon you choose so if you modify the three starters you'll also have to manually insert the new ones in the rival's team for every fight of his. Trainer party data is found at data/trainers/parties.asm or data/trainer_parties.asm for older versions, we are interested in the parties that are labelled as Green1Data, Green2Data, and Green3Data, each of these sections contains the parties of multiple encounters with the rival, save for Green3Data which is dedicated to his final fight as champion.

This is what trainer parties look like in the disassembly:
```gameboy
Green1Data:
	db 5, SQUIRTLE, 0
	db 5, BULBASAUR, 0
	db 5, CHARMANDER, 0
; Route 22
	db $FF, 9, PIDGEY, 8, SQUIRTLE, 0
	db $FF, 9, PIDGEY, 8, BULBASAUR, 0
	db $FF, 9, PIDGEY, 8, CHARMANDER, 0
; Cerulean City
	db $FF, 18, PIDGEOTTO, 15, ABRA, 15, RATTATA, 17, SQUIRTLE, 0
	db $FF, 18, PIDGEOTTO, 15, ABRA, 15, RATTATA, 17, BULBASAUR, 0
	db $FF, 18, PIDGEOTTO, 15, ABRA, 15, RATTATA, 17, CHARMANDER, 0
```

Trainer structure is the same across versions (the ones I have at least) and is very simple:
- if the byte in the db (Define Byte) instruction is $FF a level is specified for every pokémon before its name
- if anything other than $FF, every pokémon will have the same level equal to that number
- a 0 byte ends the party data

If you want a team where all pokémon have the same level you only need to specify it once at the beginning, for example:
```gameboy
; SS Anne 1F Rooms
	db 18,GROWLITHE,GROWLITHE,0
	db 19,NIDORAN_M,NIDORAN_F,0
```

![](/_resources/StartersRival.gif)

Change the name constants as you wish and we can move on to the more "complicated" part.

**POKEDEX**

This is a really small detail that I haven't seen mentioned anywhere, aside from the old one I wrote in Italian [this](https://eddmann.com/posts/changing-the-starter-pokemon-within-pokered/) is the only guide I know of and it skips this step completely, resulting in this:

![ef7d4f4fa8eb7fe3e6c982bf6267b445.png](https://eddmann.com/uploads/changing-the-starter-pokemon-within-pokered/starters.gif)

The problem is you are supposed to see the pokedex entry of the starter you interact with, there is a dedicated routine that momentarily marks the starters as caught so their entries become visible, then the bits are cleared. This way you can see all three entries but only one is actually saved once you pick the starter.

This routine is called StarterDex and can be found in its own file at engine/events/starter_dex.asm, or engine/predefs17.asm in old versions. This is the current version of the routine:
```gameboy
StarterDex:
	ld a, 1 << (DEX_BULBASAUR - 1) | 1 << (DEX_IVYSAUR - 1) | 1 << (DEX_CHARMANDER - 1) | 1 << (DEX_SQUIRTLE - 1)
	ld [wPokedexOwned], a
	predef ShowPokedexData
	xor a
	ld [wPokedexOwned], a
	ret
```

The way this works is there is a bitmask in RAM, wPokedexOwned, that is used to know exactly which pokémon you have already caught. Every pokémon's pokédex number is mapped to this bitmask, so the first instruction is using an OR bitwise operation to set the bits related to the starters' pokédex number minus one, because the pokédex counts from 1 but computer indexes start from 0. Notice how Ivysaur's dex entry is also specified for some reason, I imagine this is a little mistake made by GameFreak that the disassembly authors kept to maintain the code as faithful to the original as possible.

DEX_BULBASAUR and the other constants used are declared in constants/pokedex_constants.asm:
```text
; pokedex ids
; indexes for:
; - BaseStats (see data/pokemon/base_stats.asm)
; - MonPartyData (see data/pokemon/menu_icons.asm)
; - MonsterPalettes (see data/pokemon/palettes.asm)
	const_def 1
	const DEX_BULBASAUR  ; 1
	const DEX_IVYSAUR    ; 2
	const DEX_VENUSAUR   ; 3
	const DEX_CHARMANDER ; 4
	const DEX_CHARMELEON ; 5
	const DEX_CHARIZARD  ; 6
	const DEX_SQUIRTLE   ; 7
	const DEX_WARTORTLE  ; 8
	const DEX_BLASTOISE  ; 9
```

Obviously we need to change the dex entry to that of the new starters but there is a problem: the GameBoy has an 8-bit CPU, meaning its registers also can only store 1 byte worth of data. Technically the Zilog80 supports 16-bit operations but only using two 8-bit registers paired together: AF, BC, DE, HL.

This is a problem because the StarterDex routine is written with one fact in mind: all the dex numbers of the three default starters fit in one byte:

![dfde0dcdeffac41141001210a84851fb.png](/_resources/dfde0dcdeffac41141001210a84851fb.png)

The bit position numbers set to 1 are equal to the dex numbers of the starters minus 1, and that's convenient, but what if the number of our new starter is something like 98? We need to edit the routine a little. In order to better understand the required modification let's take a look at the older version of the routine, all that changes is the first instruction which doesn't make use of the DEX constants but instead loads the A register with a number in binary form:
```gameboy
StarterDex:
	ld a, %01001011 ; set starter flags
	ld [wPokedexOwned], a
	predef ShowPokedexData
	xor a ; unset starter flags
	ld [wPokedexOwned], a
	ret
```

This is the same number seen in the picture above (plus Ivysaur), it is copied at the beginning of the caught pokémon bitmask: wPokedexOwned, thus overwriting its first 8 bits. If we want to see the entries of higher dex entries we need to copy 8-bit blocks at different indexes of the bitmask, like so:
```gameboy
StarterDex:
    ld a, %byte1
    ld [wPokedexOwned + n1], a
    ld a, %byte2
    ld [wPokedexOwned + n2], a
    ld a, %byte3
    ld [wPokedexOwned + n3], a
    predef ShowPokedexData
    xor a
    ld [wPokedexOwned + n1], a
    ld [wPokedexOwned + n2], a
    ld [wPokedexOwned + n3], a
    ret
```

We need to replace those byte and n variables with the values obtained from this series of operations:
1) take the dex number of the first starter
2) divide the number by 8, the result is n1 (ignore decimal digits)
3) take the dex number again and do a module by 2
4) convert the module result to binary notation, this is byte1
5) if the module result is 0, then subtract 1 from n1 and set byte1's bit number 7 (the leftmost bit)
6) repeat for the other two starters

If the result of the division of two or all three starter numbers is the same then you can group n1 n2 and n3 in one or two bytes, saving yourself a few bytes in the ROM.

This is what the routine looks like for setting the starters as Growlithe, Exeggcute and Staryu:
```gameboy
StarterDex:
    ld a, %00000010                ; growlithe (58 % 8 = 2)
    ld [wPokedexOwned + 7], a      ; (58 / 8 = 7)
    ld a, %00100000                ; exeggcute (102 % 8 = 6)
    ld [wPokedexOwned + 12], a     ; (102 / 8 = 12)
    ld a, %10000000                ; staryu (120 % 8 = 0)
    ld [wPokedexOwned + 14], a     ; ((120 / 8 = 15)-1)
    predef ShowPokedexData
    xor a
    ld [wPokedexOwned + 7], a
    ld [wPokedexOwned + 12], a
    ld [wPokedexOwned + 14], a
    ret
```

The result:

![](/_resources/StartersDex.gif)


**TITLE SCREEN**

One small detail you may want to change is the first pokémon that is shown in the title screen next to the protagonist: by default this will be Charmander in Red and Squirtle in Blue (Bulbasaur was obviously in the Japanese Green version), so it may make sense to replace these with one of your starters.

Newer versions of the disassembly already do this, opening engine/movie/title.asm we see that the STARTER1 and STARTER2 macros are utilized:
```gameboy
IF DEF(_RED)
	ld a, STARTER1 ; which Pokemon to show first on the title screen
ENDC
IF DEF(_BLUE)
	ld a, STARTER2 ; which Pokemon to show first on the title screen
ENDC
```

Older versions however have hardcoded pokémon constants, they are found in engine/titlescreen.asm:
```gameboy
IF DEF(_RED)
	ld a, CHARMANDER ; which Pokemon to show first on the title screen
ENDC
IF DEF(_BLUE)
	ld a, SQUIRTLE ; which Pokemon to show first on the title screen
ENDC
```

---

And this is all you need to know to change the starters, as usual doing pretty much anything in the disassembly takes some effort, but it's also more fun than using a program that does everything automatically :)