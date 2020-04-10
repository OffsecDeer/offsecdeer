---
title: "Pokèred Guide: Scripts, how they work and how to add them"
date: 2020-03-31T01:14:17+02:00
draft: true
toc: true
showdate: true
tags:
  - rom-hacking
  - gameboy
  - pokemon
  - pokered
---

## Overly long introduction

### Why did you do this?

[pokered](https://github.com/pret/pokered), the almighty disassembly of Pokèmon Red and Blue has been out for quite a few years already and yet proper documentation on most aspects of it is still lacking.

The code is mostly commented so that people with a decent understanding of ASM programming can get their hands on it without a lot of trouble, but because of how big the repository is and how sparse the different segments related to a single mechanic are it can be difficult for anyone to put every bit together.

Back in 2015 I did some experiments with this beautiful repo and wrote down everything I discovered during my sleepless nights of "work", so I thought all those notes would be useful for people who want to get started in the niche field of Gameboy hacking.

This post is going to be the first of what I hope will become a short series of articles dedicated to pokered, where I'll be covering all the aspects I have investigated. The topic for this time is how to add new scripts to the game, much like how you would do using XSE and Advance Map in GBA games, and who knows maybe one day I'll cover third generation scripting as well.

I'll also try to detail how the scripts work and how they are managed based on my knowledge of the game's code, so this post will alternate between an "adding your own scripts tutorial" and a "how the scripts in Pokèmon Red and Blue work" kind of post.

This is not a tutorial on how to write scripts though! That will require its own much bigger and detailed article (first generation games do not make use of their own proper scripting engine, this makes writing scripts harder than it would be in GSC or RSE), here I'll be showing a couple examples of possible scripts but the whole scripting tutorial will come in the future, hopefully not too far from now.

Finally, please keep in mind that this information is taken from personal experiments and research, there might be inaccurate information since none of this was really proof read by one of the authors of the disassembly or someone with a deeper knowledge of the inner workings of the games, if you see any errors please let me know and I'll correct them immediately.

### What do I need to get started?

- a local copy of pokered
- basic GameBoy ASM knowledge
- enough patience to go through this wall of text

---

## Map object headers

Each map in the game has a header containing information on the different events it contains. Events are objects the player can interact with to trigger code and include NPCs, signs, and warps.

In order to create a new event we must change the header of the right map first. I'll be taking Pallet Town as my target map. All map headers are located at /data/mapObjects/ and look like this:

```gameboy
PalletTown_Object:
	db $b ; border block

	db 3 ; warps
	warp 5, 5, 0, REDS_HOUSE_1F
	warp 13, 5, 0, BLUES_HOUSE
	warp 12, 11, 1, OAKS_LAB

	db 4 ; signs
	sign 13, 13, 4 ; PalletTownText4
	sign 7, 9, 5 ; PalletTownText5
	sign 3, 5, 6 ; PalletTownText6
	sign 11, 5, 7 ; PalletTownText7

	db 3 ; objects
	object SPRITE_OAK, 8, 5, STAY, NONE, 1 ; person
	object SPRITE_GIRL, 3, 8, WALK, 0, 2 ; person
	object SPRITE_FISHER2, 11, 14, WALK, 0, 3 ; person

	; warp-to
	warp_to 5, 5, PALLET_TOWN_WIDTH ; REDS_HOUSE_1F
	warp_to 13, 5, PALLET_TOWN_WIDTH ; BLUES_HOUSE
	warp_to 12, 11, PALLET_TOWN_WIDTH ; OAKS_LAB
```

The border block is used when the game tries to scroll past the map's boundries and will fill the void with the specified block.

Each kind of event follows its specific format and the list of events is preceded by the number of that kind of events, so there are three warps, four signs, three NPCs, and three locations the player can warp to (these positions are used when the player walks out of a house or uses Fly). NPCs are simply called "objects" and are thus declared with the keyword *object*.  

NPCs follow this format:

```aaa
object SPRITE_NAME, X, Y, MOVEMENT1, MOVEMENT2, SCRIPT_N
```

SPRITE_NAME determines what the NPC looks like and must be a value of those included in /constants/sprite_constants.asm, which by default are:

```gameboy
; pokemon's overworld sprites
const_value = 0

	const SPRITE_MON       ; $0
	const SPRITE_BALL_M    ; $1
	const SPRITE_HELIX     ; $2
	const SPRITE_FAIRY     ; $3
	const SPRITE_BIRD_M    ; $4
	const SPRITE_WATER     ; $5
	const SPRITE_BUG       ; $6
	const SPRITE_GRASS     ; $7
	const SPRITE_SNAKE     ; $8
	const SPRITE_QUADRUPED ; $9

; overworld sprites
const_value = 1

	const SPRITE_RED                       ; $01
	const SPRITE_BLUE                      ; $02
	const SPRITE_OAK                       ; $03
	const SPRITE_BUG_CATCHER               ; $04
	const SPRITE_SLOWBRO                   ; $05
	const SPRITE_LASS                      ; $06
	const SPRITE_BLACK_HAIR_BOY_1          ; $07
	const SPRITE_LITTLE_GIRL               ; $08
	const SPRITE_BIRD                      ; $09
	const SPRITE_FAT_BALD_GUY              ; $0a
	const SPRITE_GAMBLER                   ; $0b
	const SPRITE_BLACK_HAIR_BOY_2          ; $0c
	const SPRITE_GIRL                      ; $0d
	const SPRITE_HIKER                     ; $0e
	const SPRITE_FOULARD_WOMAN             ; $0f
	const SPRITE_GENTLEMAN                 ; $10
	const SPRITE_DAISY                     ; $11
	const SPRITE_BIKER                     ; $12
	const SPRITE_SAILOR                    ; $13
	const SPRITE_COOK                      ; $14
	const SPRITE_BIKE_SHOP_GUY             ; $15
	const SPRITE_MR_FUJI                   ; $16
	const SPRITE_GIOVANNI                  ; $17
	const SPRITE_ROCKET                    ; $18
	const SPRITE_MEDIUM                    ; $19
	const SPRITE_WAITER                    ; $1a
	const SPRITE_ERIKA                     ; $1b
	const SPRITE_MOM_GEISHA                ; $1c
	const SPRITE_BRUNETTE_GIRL             ; $1d
	const SPRITE_LANCE                     ; $1e
	const SPRITE_OAK_SCIENTIST_AIDE        ; $1f
	const SPRITE_OAK_AIDE                  ; $20
	const SPRITE_ROCKER                    ; $21
	const SPRITE_SWIMMER                   ; $22
	const SPRITE_WHITE_PLAYER              ; $23
	const SPRITE_GYM_HELPER                ; $24
	const SPRITE_OLD_PERSON                ; $25
	const SPRITE_MART_GUY                  ; $26
	const SPRITE_FISHER                    ; $27
	const SPRITE_OLD_MEDIUM_WOMAN          ; $28
	const SPRITE_NURSE                     ; $29
	const SPRITE_CABLE_CLUB_WOMAN          ; $2a
	const SPRITE_MR_MASTERBALL             ; $2b
	const SPRITE_LAPRAS_GIVER              ; $2c
	const SPRITE_WARDEN                    ; $2d
	const SPRITE_SS_CAPTAIN                ; $2e
	const SPRITE_FISHER2                   ; $2f
	const SPRITE_BLACKBELT                 ; $30
	const SPRITE_GUARD                     ; $31
	const SPRITE_COP_GUARD                 ; $32
	const SPRITE_MOM                       ; $33
	const SPRITE_BALDING_GUY               ; $34
	const SPRITE_YOUNG_BOY                 ; $35
	const SPRITE_GAMEBOY_KID               ; $36
	const SPRITE_GAMEBOY_KID_COPY          ; $37
	const SPRITE_CLEFAIRY                  ; $38
	const SPRITE_AGATHA                    ; $39
	const SPRITE_BRUNO                     ; $3a
	const SPRITE_LORELEI                   ; $3b
	const SPRITE_SEEL                      ; $3c
	const SPRITE_BALL                      ; $3d
	const SPRITE_OMANYTE                   ; $3e
	const SPRITE_BOULDER                   ; $3f
	const SPRITE_PAPER_SHEET               ; $40
	const SPRITE_BOOK_MAP_DEX              ; $41
	const SPRITE_CLIPBOARD                 ; $42
	const SPRITE_SNORLAX                   ; $43
	const SPRITE_OLD_AMBER_COPY            ; $44
	const SPRITE_OLD_AMBER                 ; $45
	const SPRITE_LYING_OLD_MAN_UNUSED_1    ; $46
	const SPRITE_LYING_OLD_MAN_UNUSED_2    ; $47
	const SPRITE_LYING_OLD_MAN             ; $48
```

X and Y are the coordinates of the NPC's position in the map, if the NPC moves this is where they first will be at when the map loads. The two MOVEMENT values specify how they will behave. MOVEMENT1 can have either one of these two values:

- WALK
- STAY

While MOVEMENT2 can either be a number or one of these macro values to tell exactly in which directions the NPC will look at in case it's set to STAY:

- UP
- DOWN
- LEFT
- RIGHT
- NONE (!!!check behavior!!!)

The numeric values are used to make an NPC look in different directions dynamically when STAYing or to tell in which directions they'll walk:

- 0 = more articulated version of number 3
- 1 = look / move up and down
- 2 = look / move left and right
- 3 = look / move in all directions

Finally, SCRIPT_N specifies what map script to call when the object is interacted with. So if I wanted to place a fisher NPC in the map I would change the objects section of the file like so:

```gameboy
db 4 ; objects
object SPRITE_OAK, 8, 5, STAY, NONE, 1 ; person
object SPRITE_GIRL, 3, 8, WALK, 0, 2 ; person
object SPRITE_FISHER2, 11, 14, WALK, 0, 3 ; person
object FISHER, 5, 5, WALK, 1, 8
```

The coordinates for a position of your choice can be obtained easily by looking at the map with ClassicMap.

Note that the number on top has been incremented by one to make room in the header for a new object and the script number is 8 because signs have their own script as well, so in Pallet Town you have three scripts dedicated to NPCs and four for signs.

TODO: APPARENTLY ONE CANNOT USE A GREATER SCRIPT_N THAN THE NUMBER OF SIGNS, CHECK THIS!!!

---

## Understanding the scripting format

Once the map header has been edited we are ready to write the actual script. Open the file relative to the map in the /scripts/ directory, for example /scripts/PalletTown.asm.

The script files are a little complicated and don't work in the simplest of ways so bear with me.

### **Map scripts**

The files begin with the game checking whether there are special scripts to be executed or not depending on flags that are set and unset when the player makes progress:

```gameboy
PalletTown_Script:
	CheckEvent EVENT_GOT_POKEBALLS_FROM_OAK
	jr z, .next
	SetEvent EVENT_PALLET_AFTER_GETTING_POKEBALLS
.next
	call EnableAutoTextBoxDrawing
	ld hl, PalletTown_ScriptPointers
	ld a, [wPalletTownCurScript]
	jp CallFunctionInTable
```

This regulates the flow of the game, special scripts that only need to be executed once and are needed to progress with the game are called in this routine if the right criteria is met.

In the code above the game is checking whether the player has already obtained their first Pokèmon from the professor, if they have then a new flag is set and this will allow the player to go out of the map.

The .next segment of the code loads the list of main scripts of the map in HL, this is a pointer table declared right after the code:

```gameboy
PalletTown_ScriptPointers:
	dw PalletTownScript0
	dw PalletTownScript1
	dw PalletTownScript2
	dw PalletTownScript3
	dw PalletTownScript4
	dw PalletTownScript5
	dw PalletTownScript6
```

These are the pointers that contain the address in memory of each script in the map. Then a special value is taken from RAM, wPalletTownCurScript, which is a special address in memory used by the game to know which special script to execute, and the CallFunctionInTable function is executed to call the script that had just been loaded in A.

This cycle keeps taking place as the player is in the map, if no special script has to be executed at that point in time the player will not even notice this is happening in the background.

By "main scripts" (sometimes called "map scripts" in some old documents) I mean all the scripts the game keeps checking for at the beginning of a script file. These scripts are usually triggered when the player is in a specific position or if certain conditions are met, typically without the player's interaction with an object.

You may want to add your script in this section of the file for example if you want an NPC to only show up at a specific part of the game, or more in general if the game itself has to check if it's the right time to execute the script instead of having it execute when the player interacts with an object.

This is an example of special script that only needs to be executed once, the first one in Pallet Town, where Oak stops Red from getting out of the map:

```gameboy
PalletTownScript0:
	CheckEvent EVENT_FOLLOWED_OAK_INTO_LAB
	ret nz
	ld a, [wYCoord]
	cp 1 ; is player near north exit?
	ret nz
	xor a
	ld [hJoyHeld], a
	ld a, PLAYER_DIR_DOWN
	ld [wPlayerMovingDirection], a
	ld a, $FF
	call PlaySound ; stop music
	ld a, BANK(Music_MeetProfOak)
	ld c, a
	ld a, MUSIC_MEET_PROF_OAK ; “oak appears” music
	call PlayMusic
	ld a, $FC
	ld [wJoyIgnore], a
	SetEvent EVENT_OAK_APPEARED_IN_PALLET

	; trigger the next script
	ld a, 1
	ld [wPalletTownCurScript], a
	ret
```

In this case the script is checking if Oak was already followed in his lab and also the player's position, because this only has to execute when the player is trying to walk out of the map, in fact the game checks if the player's Y coordinate is 1, the top of the map that would lead to route 1.

If the script executes at the end it updates the value of wPalletTownCurScript to trigger the next one at the next iteration of the cycle.

In order to add your own special script you must add a new script pointer declaration in the pointer table above, like:

```gameboy
dw PalletTownScript7
```

But keep in mind that the format and order of these scripts in the file depend heavily on the logic you want behind them. In Pallet Town it's easy because they are all executed one after the other so wPalletTownCurScript is simply increased every time until it reaches the last script, number 6, which does nothing:

```gameboy
PalletTownScript5:
	CheckEvent EVENT_DAISY_WALKING
	jr nz, .next
	CheckBothEventsSet EVENT_GOT_TOWN_MAP, EVENT_ENTERED_BLUES_HOUSE, 1
	jr nz, .next
	SetEvent EVENT_DAISY_WALKING
	ld a, HS_DAISY_SITTING
	ld [wMissableObjectIndex], a
	predef HideObject
	ld a, HS_DAISY_WALKING
	ld [wMissableObjectIndex], a
	predef_jump ShowObject
.next
	CheckEvent EVENT_GOT_POKEBALLS_FROM_OAK
	ret z
	SetEvent EVENT_PALLET_AFTER_GETTING_POKEBALLS_2
PalletTownScript6:
	ret
```

Whatever you do in this section of the file, make sure your scripts only execute once by checking for the proper flags with CheckEvent and eventually returning, or by changing the CurScript value of the map manually if you need to alter the execution flow at the next cycle.

There can of course be maps with no special scripts, such as Route 1, which begins like this:

```gameboy
Route1_Script:
	jp EnableAutoTextBoxDrawing
```

But if a map has trainers the code to handle them needs to be added to the map scripts section too (trainers and how they work will be talked about in detail in the future), let's take Route 8 for example:

```gameboy
Route8_Script:
	call EnableAutoTextBoxDrawing
	ld hl, Route8TrainerHeader0
	ld de, Route8_ScriptPointers
	ld a, [wRoute8CurScript]
	call ExecuteCurMapScriptInTable
	ld [wRoute8CurScript], a
	ret

Route8_ScriptPointers:
	dw CheckFightingMapTrainers
	dw DisplayEnemyTrainerTextAndStartBattle
	dw EndTrainerBattle
```

---

### **Text scripts**

So called "text scripts" only execute when the player interacts with an object, making them the most common kind of script including normal NPCs and signs. Unless your script has special requirements it should belong here.

Text scripts start right after the end of map scripts with the declaration of all the text script pointers in its own pointer table:

```gameboy
PalletTown_TextPointers:
	dw PalletTownText1
	dw PalletTownText2
	dw PalletTownText3
	dw PalletTownText4
	dw PalletTownText5
	dw PalletTownText6
	dw PalletTownText7
```

Text scripts can be very simple, in the case of a sign or of an NPC who only gives the player a single message every time the code would look like this:

```gameboy
PalletTownText3: ; fat man
	TX_FAR _PalletTownText3
	db "@"
```

The "@" is used to separate text scripts from one another so it has to be at the end of all of those that start with TX_FAR.

TX_FAR is a macro used to make scripts simpler by not repeating a bunch of code. This is what the macro looks like under the hood (/macros/text_macros.asm):

```gameboy
TX_FAR: MACRO
	db $17
	dw \1
	db BANK(\1)
ENDM
```

It takes a pointer as argument and places the byte $17 in the ROM followed by the argument itself (a pointer, so two bytes) and its bank number (refer to [this post](/post/gb-pointers/) for ROM banks).

All TX_FAR needs to show a message to the player is the name of the message pointer, which is declared in another file which will be seen later. That is literally all the code required for a very simple script, given that you have added your own pointer to the pointer table as well, of course.

On the other hand more sophisticated scripts can make use of branching, loops, and a lot of subroutines to perform specific actions. For example this is the script that gives the player a town map:

```gameboy
BluesHouseText1:
	TX_ASM
	CheckEvent EVENT_GOT_TOWN_MAP
	jr nz, .GotMap
	CheckEvent EVENT_GOT_POKEDEX
	jr nz, .GiveMap
	ld hl, DaisyInitialText
	call PrintText
	jr .done

.GiveMap
	ld hl, DaisyOfferMapText
	call PrintText
	lb bc, TOWN_MAP, 1
	call GiveItem
	jr nc, .BagFull
	ld a, HS_TOWN_MAP
	ld [wMissableObjectIndex], a
	predef HideObject ; hide table map object
	ld hl, GotMapText
	call PrintText
	SetEvent EVENT_GOT_TOWN_MAP
	jr .done

.GotMap
	ld hl, DaisyUseMapText
	call PrintText
	jr .done

.BagFull
	ld hl, DaisyBagFullText
	call PrintText
.done
	jp TextScriptEnd
```

Text scripts that do not just display a message on screen have to start with the TX_ASM macro, which just places a single byte in the ROM in front of the script's code itself:

```gameboy
TX_ASM     EQUS "db $08"
```

This macro is needed to let the game know how to handle the data that follows, a $08 means "script ahead", while $17 means "message pointer ahead" (TX_FAR).

Anyway, the script makes use of subroutines such as PrintText and GiveItem as well as macros like CheckEvent and SetEvent, and finally the predefs, like HideObject, which are much like subroutines but need to be called with the "predef" macro. These special subroutines reside in a table and are managed by the disassembly thanks to these macros:

```gameboy
; Predef macro.
predef_const: MACRO
	const \1PredefID
ENDM

add_predef: MACRO
\1Predef::
	db BANK(\1)
	dw \1
ENDM

predef_id: MACRO
	ld a, (\1Predef - PredefPointers) / 3
ENDM

predef: MACRO
	predef_id \1
	call Predef
ENDM

predef_jump: MACRO
	predef_id \1
	jp Predef
ENDM
```

So that they can simply be called by their name.

A list of the macros, subroutines, and predefs I have experimented with so far will be part of a future scripting tutorial, but a full list of predefs is found at /engine/predefs.asm:

```gameboy
PredefPointers::
; these are pointers to ASM routines.
; they appear to be used in overworld map scripts.
	add_predef DrawPlayerHUDAndHPBar
	add_predef CopyUncompressedPicToTilemap
	add_predef AnimateSendingOutMon
	add_predef ScaleSpriteByTwo
	add_predef LoadMonBackPic
	add_predef CopyDownscaledMonTiles
	dbw $03,JumpMoveEffect ; wrong bank
	add_predef HealParty
	add_predef MoveAnimation
	add_predef DivideBCDPredef
	add_predef DivideBCDPredef2
	add_predef AddBCDPredef
	add_predef SubBCDPredef
	add_predef DivideBCDPredef3
	add_predef DivideBCDPredef4
	add_predef InitPlayerData
	add_predef FlagActionPredef
	add_predef HideObject
	add_predef IsObjectHidden
	add_predef ApplyOutOfBattlePoisonDamage
	add_predef AnyPartyAlive
	add_predef ShowObject
	add_predef ShowObject2
	add_predef ReplaceTileBlock
	add_predef InitPlayerData2
	add_predef LoadTilesetHeader
	add_predef LearnMoveFromLevelUp
	add_predef LearnMove
	add_predef GetQuantityOfItemInBag
	dbw $03,CheckForHiddenObjectOrBookshelfOrCardKeyDoor ; home bank
	dbw $03,GiveItem ; home bank
	add_predef ChangeBGPalColor0_4Frames
	add_predef FindPathToPlayer
	add_predef PredefShakeScreenVertically
	add_predef CalcPositionOfPlayerRelativeToNPC
	add_predef ConvertNPCMovementDirectionsToJoypadMasks
	add_predef PredefShakeScreenHorizontally
	add_predef UpdateHPBar
	add_predef HPBarLength
	add_predef Diploma_TextBoxBorder
	add_predef DoubleOrHalveSelectedStats
	add_predef ShowPokedexMenu
	add_predef EvolutionAfterBattle
	add_predef SaveSAVtoSRAM0
	add_predef InitOpponent
	add_predef CableClub_Run
	add_predef DrawBadges
	add_predef ExternalClockTradeAnim
	add_predef BattleTransition
	add_predef CopyTileIDsFromList
	add_predef PlayIntro
	add_predef GetMoveSoundB
	add_predef FlashScreen
	add_predef GetTileAndCoordsInFrontOfPlayer
	add_predef StatusScreen
	add_predef StatusScreen2
	add_predef InternalClockTradeAnim
	add_predef TrainerEngage
	add_predef IndexToPokedex
	add_predef DisplayPicCenteredOrUpperRight
	add_predef UsedCut
	add_predef ShowPokedexData
	add_predef WriteMonMoves
	add_predef SaveSAV
	add_predef LoadSGB
	add_predef MarkTownVisitedAndLoadMissableObjects
	add_predef SetPartyMonTypes
	add_predef CanLearnTM
	add_predef TMToMove
	add_predef _RunPaletteCommand
	add_predef StarterDex
	add_predef _AddPartyMon
	add_predef UpdateHPBar2
	add_predef DrawEnemyHUDAndHPBar
	add_predef LoadTownMap_Nest
	add_predef PrintMonType
	add_predef EmotionBubble
	add_predef EmptyFunc3; return immediately
	add_predef AskName
	add_predef PewterGuys
	add_predef SaveSAVtoSRAM2
	add_predef LoadSAV2
	add_predef LoadSAV
	add_predef SaveSAVtoSRAM1
	add_predef DoInGameTradeDialogue
	add_predef HallOfFamePC
	add_predef DisplayDexRating
	dbw $1E, _LeaveMapAnim ; wrong bank
	dbw $1E, EnterMapAnim ; wrong bank
	add_predef GetTileTwoStepsInFrontOfPlayer
	add_predef CheckForCollisionWhenPushingBoulder
	add_predef PrintStrengthTxt
	add_predef PickUpItem
	add_predef PrintMoveType
	add_predef LoadMovePPs
	add_predef DrawHP
	add_predef DrawHP2
	add_predef DisplayElevatorFloorMenu
	add_predef OaksAideScript
```

Meanwhile, the other ASM subroutines are scattered here and there throughout the ROM. Quite a few of them are in /home.asm, like GiveItem and GivePokemon:

```gameboy
GiveItem::
; Give player quantity c of item b,
; and copy the item's name to wcf4b.
; Return carry on success.
	ld a, b
	ld [wd11e], a
	ld [wcf91], a
	ld a, c
	ld [wItemQuantity], a
	ld hl, wNumBagItems
	call AddItemToInventory
	ret nc
	call GetItemName
	call CopyStringToCF4B
	scf
	ret

GivePokemon::
; Give the player monster b at level c.
	ld a, b
	ld [wcf91], a
	ld a, c
	ld [wCurEnemyLVL], a
	xor a ; PLAYER_PARTY_DATA
	ld [wMonDataLocation], a
	jpba _GivePokemon
```

Most of the times finding the declaration of a scripting subroutine in the source code means finding comments specifying how to use it, like in the example above.

Going back to the town map script, branching is achieved with simple relative jumps that take to labels such as .BagFull in case there's no more room for the map, .done if the player was already given the map, and so on.

You might have noticed that TX_FAR is not used to show text in scripts that start with TX_ASM, instead the PrintText routine is called after loading HL with the pointer of the desired message to display:

```gameboy
.GotMap
	ld hl, DaisyUseMapText
	call PrintText
	jr .done

.BagFull
	ld hl, DaisyBagFullText
	call PrintText
.done
	jp TextScriptEnd
```

But there are also instances where it is used, for example on Route 1 there's a Pokèmon Mart employee that gives the player a potion, and in her script the text is displayed with both methods:

```gameboy
Route1Text1:
	TX_ASM
	CheckAndSetEvent EVENT_GOT_POTION_SAMPLE
	jr nz, .asm_1cada
	ld hl, Route1ViridianMartSampleText
	call PrintText
	lb bc, POTION, 1
	call GiveItem
	jr nc, .BagFull
	ld hl, Route1Text_1cae8
	jr .asm_1cadd
.BagFull
	ld hl, Route1Text_1caf3
	jr .asm_1cadd
.asm_1cada
	ld hl, Route1Text_1caee
.asm_1cadd
	call PrintText
	jp TextScriptEnd

Route1ViridianMartSampleText:
	TX_FAR _Route1ViridianMartSampleText
	db "@"

Route1Text_1cae8:
	TX_FAR _Route1Text_1cae8
	TX_SFX_ITEM_1
	db "@"

Route1Text_1caee:
	TX_FAR _Route1Text_1caee
	db "@"

Route1Text_1caf3:
	TX_FAR _Route1Text_1caf3
	db "@"
```

I still have to check if there are differences between PrintText and TX_FAR messages.

Also, all text scripts that do not begin with TX_FAR must end with the following instruction:

```gameboy
jp TextScriptEnd
```

Another little detail to note is how the GiveItem routine will not play any sound effect when the item is given to the player, instead, another text macro is used after the pointer to the message that says "player got item!":

```gameboy
Route1Text_1cae8:
	TX_FAR _Route1Text_1cae8
	TX_SFX_ITEM_1
	db "@"
```

GiveItem doesn't show any text dialog either so one needs to be added manually like so:

```gameboy
_Route1Text_1cae8::
	text "<PLAYER> got"
	line "@"
	TX_RAM wcf4b
	text "!@@"
```

The next section talks about how to add text files. There appear to be two different sound effect macros for received items, SHOULD CHECK THE DIFFERENCE!!!!:

```gameboy
TX_SFX_ITEM_1         EQUS "db $0b"
TX_SFX_ITEM_2         EQUS "db $10"
```

---

## Text location and format

Actual scripts and the text associated with them are located in different directories, unlike in the games where it can all put into one single script file which the interpreter will then save in the proper locations.

All the text references by scripts can be found in the /text/maps/ directory divided by maps. Let's keep using Pallet Town as a reference:

```gameboy
_OakAppearsText::
	text "OAK: Hey! Wait!"
	line "Don't go out!@@"

_OakWalksUpText::
	text "OAK: It's unsafe!"
	line "Wild #MON live"
	cont "in tall grass!"

	para "You need your own"
	line "#MON for your"
	cont "protection."
	cont "I know!"

	para "Here, come with"
	line "me!"
	done

_PalletTownText2::
	text "I'm raising"
	line "#MON too!"

	para "When they get"
	line "strong, they can"
	cont "protect me!"
	done

_PalletTownText3::
	text "Technology is"
	line "incredible!"

	para "You can now store"
	line "and recall items"
	cont "and #MON as"
	cont "data via PC!"
	done

_PalletTownText4::
	text "OAK #MON"
	line "RESEARCH LAB"
	done

_PalletTownText5::
	text "PALLET TOWN"
	line "Shades of your"
	cont "journey await!"
	done

_PalletTownText6::
	text "<PLAYER>'s house "
	done

_PalletTownText7::
	text "<RIVAL>'s house "
	done
```

These pointers begin with an underscore by convention to differentiate them from the pointer name of the script that uses them, they end with a double colon after which a set of text macros can be used to decide how exactly the message box will behave while displaying the text:

```gameboy
; text macros
text   EQUS "db $00," ; Start writing text.
next   EQUS "db $4e," ; Move a line down.
line   EQUS "db $4f," ; Start writing at the bottom line.
para   EQUS "db $51," ; Start a new paragraph.
cont   EQUS "db $55," ; Scroll to the next line.
done   EQUS "db $57"  ; End a text box.
prompt EQUS "db $58"  ; Prompt the player to end a text box (initiating some other event).
```

Adding your own text here is trivial as long as the right format is followed and you reference the right pointer in your script, just add the new dialog at the end of the already existing ones, but be careful not to .
PLAYER, RIVAL, and #MON are macros.



---































