---
title: "Pointers on the GameBoy and how to repoint them"
date: 2019-08-24T17:37:49+02:00
tags:
  - rom-hacking
  - gameboy
showdate: true
toc: true
---

This topic has already been covered multiple times on many different websites by different people, but because I want the series of ROM hacking posts on my blog to be somewhat complete and being able to link back to some theory posts would be useful for more advanced topic I'll be talking about in the future, I decided to make my own post on how pointers are used in GameBoy games, why they are so important, and how the repointing process works, as it's a matter that I've seen creating quite some confusion among new hackers.

---

## Pointers?

If you have done some C or C++ programming you most likely already know what a pointer is and what it's used for, but not everyone has such a background so I'm going to spend a few minutes talking about them from a very basic level, you can skip this section if you are already familiar with them.

Pointers are essentially variables, in programming variables are often seen as boxes with a label and some arbitrary content. The label on the box represents the name of the variable, so the alias that programmers use to refer to it while writing code, and the content can vary a lot depending on the kind of variable, languages like C are very strict on the concept of types and the programmer must define one for each variable they create, but others like Python are more flexible and can detect by themselves how to treat a variable based on what the programmers put into them.

Because they are essentially boxes, variables are used to store data that the program might need later during execution, such data can consist in numbers of various kinds, characters, and all derivates of these, like strings, which in C are nothing but arrays of characters, or decimal numbers, negative numbers, and so on.

Pointers are a special kind of variable because unlike the rest of them it will not contain some direct data, a pointer will contain the address in memory of some data the programmer will need. Pointers make execution faster and allow programmers to create structures such as tables where data is organized in an easy to access way, making their lives easier when they have to work with the data contained in these tables. To make it short, pointers are used to know where data is located in memory, if we want to alter some of that data for our hacking purposes we need to tell the game where this new data is by changing the values of the pointers, this process is called repointing.

![img](/images/gb-pointers/1.png)
[(source)](http://jinsoft.in/1st-semester-engineers-nightmare-pointers-in-c/)

---

## Pointers on the GameBoy

In GameBoy games pointers are often organized in *pointer tables*, which are areas in memory where different pointers are located, one after the other. These tables are specialized, meaning they all point to different elements of a list or to different structures that are all related to each other between pointers of the same table.

The reason why they are so important and we are interested in changing these pointers' values is that when we go ROM hacking we have some limitations, when we want to alter some data, say for example a script, we can only use the same area in memory the original script uses or else the game wouldn't know where else to find it, and if we accidentally write one byte more than the original script we end up overwriting other data that may belong to another script or other important stuff, so we always have very limited space to work with. But... what if we told the game to look for the data somewhere else?

ROMs of GameBoy games are divided into many different sections called *ROM banks*, each bank is 0x4000 bytes big (0x = [hexadecimal notation](https://en.wikipedia.org/wiki/Hexadecimal)) and the GameBoy's Zilog80 CPU cannot access data located in two different banks at the same time, it needs to do a *bank switch* first, and at that point the old bank will be inaccessible until the CPU switches back to it. We need to know this because usually the game will never use all those 0x4000 bytes in each bank, game programmers used to save data of different kinds on different banks instead of cramming all of it into contiguous spaces, which means we may find scripts in bank 1, maps in bank 2, graphics in bank 3, sounds and music in bank 4, and so on, but of course different developers adopted different strategies. This means that banks were rarely completely full, in fact, if we take a look at any GameBoy game with a hex editor we'll find that at the end of many banks there will be a lot of empty room filled with zeros. To verify this, pick a random memory address from any game and use this simple formula:

```shell-session
bankBaseAddress = (offset / 0x4000) * 0x4000
```

This calculates the beginning in memory of the desired bank. The division tells us what bank number we are in, and multiplying by 0x4000 gives us the right address of where the bank begins. Do the calculation with a random address picked from any game, jump to it with your hex editor of choice, and take a look at the addresses right *before* where you landed:

![img](/images/gb-pointers/2.png)

The red square is memory address 0x8000 inside the ROM of Pokèmon Blue, beginning of the second ROM bank. As you can see what preceeds it is a whole lot of zeros, all unused memory we can take advantage of, in fact, this is what repointing is all about, finding unused memory regions where to add our new data which would be too big to just overwrite the original, find the pointer that tells the game where to find the data we're interested in altering, and changing the value of the pointer to make it point to the address where we added our new content.

Keep in mind though, not every bank has that much free space in it, for example, bank number 3 is much more full and only has a few free bytes at the end:

![img](/images/gb-pointers/3.png)

---

## Repointing

Luckily for us pointers follow a very specific structure and so it's relatively easy to find where the pointer pointing at a memory address of our interest is located, we cannot calculate their memory address but we can calculate their content, and knowing that pointers are usually located in tables we know a pointer will be adjacent to many others which will look pretty similar, and if the game we are hacking has a [ROM map](https://datacrystal.romhacking.net/wiki/ROM_map) available we can look up the desired pointers there.

```shell-session
pointer = (offset % 0x4000) + 0x4000
```

The result will always be two bytes long. Because the GameBoy works in [little endian](https://en.wikipedia.org/wiki/Endianness) we must swap the two bytes. For example:

```shell-session
pointer = (0xD0DF % 0x4000) + 0x4000 = 0x50DF ---> 0x50 0xDF ---> 0xDF 0x50 ---> 0xDF50
```

*offset* is the memory address of our choice, and the result of this operation (% = mod) returns us the value the pointer we're looking for is holding. We can now consult our ROM map of choice to see where the table we're interested in is located, it will give us the base address of the table, so where the first element is located. Navigate to that address and look for the values that were obtained. In my example I got that memory address from the wild Pokèmon data in route 1 on Pokèmon Blue, so from the ROM map of the game I found that the Wild Pokèmon data pointers start at 0xCEEB, and sure enough, just a few bytes ahead:

![img](/images/gb-pointers/4.png)

The red square is address 0xCEEB, beginning of the pointer table, which starts with a bunch of filler values until the first actual entry is met, at address 0xCF03. Good, now we have identified the pointer we must work with, now we must calculate the right value to overwrite it with in order to make it point to our new data. Remember that the data must be in the same ROM bank as the pointer, unless it's a 3 bytes pointer, which I'll explain later, but those are rarer. To calculate said value we can use the same formula above but with the new address we want to repoint to instead, so if for example I added some data at address 0xE002 I would do:

```shell-session
newPointer = (0xE002 % 0x4000) + 0x4000 = 0x6002 ---> 0x60 0x02 ---> 0x02 0x60 ---> 0x0260
```

So I'll have to change DF50 into 0260, and that will tell the game to look for the data in the new location where we added it instead of the old one, which can always be re-used if needed.

---

## 3 Bytes Pointers

A set of cartridges for the GameBoy and GameBoy Color have inside an interesting integrated circuit called [Memory Bank Controller](http://gbdev.gg8.se/wiki/articles/Memory_Bank_Controllers) (MBC), it's a chip that allowed programmers to have access to more than 32 Kbytes of space (the default storage available in a GB cartridge) in the cartridge by performing bank switching, effectively giving them the ability to gather data from any bank they wanted regardless of where the code was being executed at that moment. 3 bytes pointers are structured this way:

```shell-session
[B] [A] [BANK_NUMBER]
```

It's the same as a two bytes pointer but with an extra byte telling the game in what bank the desired data is located, so at the end of the day nothing really changes, if anything these pointers give us a lot more flexibility because we can repoint them everywhere we want in the ROM, as long as we set the BANK_NUMBER byte properly. Note that BANK_NUMBER *isn't* always located right next to the pointer itself, sometimes it can be a few bytes ahead, consult the ROM maps. If in doubt and if you know what data these pointers are pointing at try calculating the data's bank number and look for that number near the area of the pointers.

---

## Inverse Formula

If you need to calculate the memory address pointed to by a pointer you have already identified there is another formula that can be used:

```shell-session
dataAddress = (bankNumber * 0x4000) + (pointer - 0x4000)
```

This returns an absolute offset to the data pointed at by the pointer, it works with both kinds, 2 and 3 bytes. Remember that when doing this calculation *pointer* must be switched back to big endian if you're reading its data straight from a hex editor. The bank number can be calculated with a simple division:

```shell-session
bankNumber = address / 0x4000
```

---

I think this is enough theory for now. It's more for curious people since there are many pointer calculators nowadays and those make everything a bit easier, but for those who wanted to know how it works behind the scenes, here you have it. I have written my own calculator in C# so if you want to give it a look go ahead, but it's very basic.
