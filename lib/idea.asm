; Last updated: Wed Sep 18 1996

; Tiny IDEA Encryption Program
; Copyright (C) Fauzan Mirza 1995-96

; Version 3A (DOS specific, smallest)

; Optimized for smaller CODE size by Mark Andreas <voyageur@sky.net>

        .model  tiny
        .code

        org     100h

BuffLen equ     32768                   ; File buffer size
PassLen equ     128                     ; Passphrase length

Start:
        call    Burn

        mov     dx,offset Usage
        mov     si,80h
        lodsb
        or      al,al                   ; Check if parameters specified
        jz      PrintUsage

        lodsb
        lodsb                           ; Get mode switch
        cmp     al,'-'
        jz      DeMode
        cmp     al,'+'
        jz      EnMode
PrintUsage:
        jmp     Exit

DeMode:
        inc     byte ptr [Mode]
EnMode:
        lodsw

AddZero:
        lodsb
        cmp     al,20h
        ja      AddZero
        mov     byte ptr [si-1],cl      ; null-terminate string

        mov     dl,offset Enterkey-512  ; OPTIMIZATION: dh = 512 = MSB(Enterkey)
        mov     ah,9
        int     21h                     ; Print message requesting key

        mov     dl,offset Password-512  ; OPTIMIZATION: dh = 512 = MSB(Password)
        mov     ah,0ah
        int     21h                     ; Get passphrase from user

        mov     cl,PassLen/8            ; Hash passphrase down to 128 bits
        mov     si,offset Passphrase

h       equ     Key
g       equ     Key+8

TandemDM:
        push    cx              ; push block counter    <0
        push    si              ; push data             <1

        mov     cl,4
        mov     si,offset g     ; -- Let first half of key = second half of hash (G)
        mov     di,offset hashKey
        rep     movsw           ; after: di->key+8

        pop     si              ; si->data              1>
        push    si              ; push data             <1
        call    Convert         ; -- Let second half of key = data

        mov     si,offset hashKey
        push    si              ; push key              <2
        mov     di,si
        call    Expandkey       ; -- Expand key : Key = {G, data}

        mov     cl,4
        mov     si,offset h
        mov     di,offset w_val
        push    di              ; push w                <3
        rep     movsw           ; -- Let W = first half of hash (H)

        pop     di              ; di->w                 3>
        pop     si              ; si->key               2>
        push    si              ; push key              <2

        call    IDEA            ; -- W = IDEA encrypt (W, {G,data})

        mov     si,di           ; si->w
        mov     di,offset h
        call    doGHsub         ; -- Update H with (H xor W)

        pop     di              ; di->key               2>
        pop     si              ; si->data              1>
        push    si              ; push data             <1
        push    di              ; push key              <2
        call    Convert         ; -- Let first half of key = data

        mov     cl,4
        mov     si,offset w_val ; di->key+8
        rep     movsw           ; -- Let second half of key = W

        pop     si              ; si->key               2>
        mov     di,si
        call    Expandkey       ; -- Expand key : Key = {data, W}

        mov     cl,4
        mov     si,offset g
        mov     di,offset g0
        push    si              ; push g                <2
        push    di              ; push g0               <3
        rep     movsw           ; -- Let G0 = G

        pop     di              ; di->g0                3>
        push    di              ; push g0               <3
        mov     si,offset hashKey
        call    IDEA            ; -- G0 = IDEA encrypt (G0, {data, W})

        pop     si              ; si->g0                3>
        pop     di              ; di->g                 2>

        call    doGHsub         ; -- Update G with (G xor G0)

        pop     si              ; si->data              1>
        add     si,8            ; data+=8
        pop     cx              ; cx=block counter      0>
        loop    TandemDM        ; -- Continue hashing until no more blocks

        mov     di,offset Key   ; Expand hashed passphrase to IDEA key
        call    Expandkey

        mov     dx,0084h
        mov     ax,3d02h
        int     21h                     ; Open file with R/W access
        jc      Errstop
        xchg    bx,ax

Again:
        mov     cx,BuffLen
        mov     dx,offset Buffer
        mov     ah,3fh
        int     21h                     ; Read upto 32k into buffer
Errstop:
        jc      Error

        or      ax,ax                   ; Check if we reached EOF
        jz      Done

        push    dx                      ; offset Buffer
        push    ax                      ; bytes read
        push    bx                      ; file handle

; Encrypt Buffer

        mov     di,dx                   ; DI -> data (start)

        add     ax,7
        mov     cl,3
        shr     ax,cl
        xchg    cx,ax                   ; CX = number of blocks to encrypt
Block:
        mov     si,offset Key
        push    cx
        push    di                      ; Save current position

        mov     di,offset CFBBuffer     ; Encrypt 8 byte CFB buffer (DI)
        call    IDEA
        mov     cx,4                    ; Process 4 words
        pop     si                      ; SI -> data, DI -> CFB buffer

Mode:
        clc                             ; OPTIMIZATION: decrypt -> stc
        jc      Decrypt

; Cipher Feedback

Encrypt:
        lodsw                           ; Get a word from file buffer
        xchg    ah,al                   ;   and convert it to little-endian
        xor     ax,word ptr [di]        ; XOR data with CFB buffer
        stosw                           ; Replace ciphertext in CFB buffer
        xchg    ah,al                   ; Convert back to big-endian
        mov     word ptr [si-2],ax      ;   and store in file buffer
        loop    Encrypt

        jmp     short DoNextBlock       ; Skip over Decrypt routine

Decrypt:
        mov     bx,word ptr [di]        ; Get word from CFB buffer
        lodsw                           ; Get word from file buffer
        xchg    ah,al                   ;   convert it to little-endian
        stosw                           ; Update CFB buffer
        xor     bx,ax                   ; XOR data with CFB buffer
        xchg    bh,bl                   ; Convert back to big-endian
        mov     word ptr [si-2],bx      ;   and store in file buffer
        loop    Decrypt

DoNextBlock:
        mov     di,si                   ; Update block counter
        pop     cx
        loop    Block                   ; Continue until all blocks processed

; Buffer Encrypted

        pop     bx                      ; file handle

        pop     dx
        push    dx                      ; bytes read

        neg     dx
        dec     cx                      ; CX = FFFF
        mov     ax,4201h
        int     21h                     ; Seek backwards

        pop     cx                      ; bytes read
        pop     dx                      ; offset Buffer
        mov     ah,40h
        int     21h                     ; Write encrypted buffer
        jnc     Again                   ; Continue until no more data

Error:
        mov     dx,offset Message
Exit:
        mov     ah,09
        int     21h                     ; Display message

Done:
        ; Burn evidence and exit

Burn:
        mov     di,offset Passphrase-1
        mov     cx,Buffer-Passphrase+BuffLen+1
        rep     stosb                   ; Overwrite data area
        ret                             ; Exit

; Convert string to little-endian words
; (called by Tandem DM hashing routine)

Convert:
        mov     cl,4
CopyLoop:
        lodsw
        xchg    ah,al
        stosw
        loop    CopyLoop
        ret

; XOR update 64-bit buffer
; (called by Tandem DM hashing routine)

doGHsub:
        mov     cx,4
doGHloop:
        lodsw
        xor     ax,[di]
        stosw
        loop    doGHloop
        ret

; Expand user key to IDEA encryption key
; Entry:  si -> userkey, di -> buffer for IDEA key (can equal si)
; Exit:   di -> IDEA key

Expandkey:
        add     di,16
        mov     bl,8
Rotate:
        mov     ax,bx                   ; Determine which two of the previous
        and     al,7                    ;  eight words are needed for this
        cmp     al,6                    ;  key expansion round

        mov     ax,word ptr [di-14]
        mov     dx,word ptr [di-12]
        jb      Update
        mov     dx,word ptr [di-28]
        jz      Update
        mov     ax,word ptr [di-30]
Update:
        mov     cl,9
        shl     ax,cl
        mov     cl,7
        shr     dx,cl                   ; Calculate the rotated value
        or      ax,dx
        stosw                           ;   and save it
        inc     bx
        cmp     bl,52
        jnz     Rotate                  ; Continue until 52 words updated
        ret

; IDEA subroutine
; Entry:  si -> key, di -> input data
; Exit:   di -> output data, all other registers trashed

; Refer to the PGP IDEA source for a better explanation
; of the algorithm and the optimisations

; Thanks to Bill Couture <bcouture@cris.com> for speed optimisations

x0      equ     bx
x1      equ     cx
x2      equ     bp
x3      equ     di

IDEA:
        mov     byte ptr [Rounds],8     ; Eight rounds
        push    di
        mov     dx,word ptr [di]
        mov     x1,word ptr [di+2]
        mov     x2,word ptr [di+4]
        mov     x3,word ptr [di+6]      ; note that DI is over-written last
Round:
        call    MulMod
        xchg    x0,ax                   ; x0 *= *key++

        lodsw
        add     x1,ax                   ; x1 += *key++
        lodsw
        add     x2,ax                   ; x2 += *key++
        mov     dx,x3
        call    MulMod
        xchg    x3,ax                   ; x3 *= *key++

        push    x1                      ; s0 = x1
        push    x2                      ; s1 = x2
        xor     x2,x0                   ; x2 ^= x0
        xor     x1,x3                   ; x1 ^= x3

        mov     dx,x2
        call    MulMod
        add     x1,ax                   ; x2 *= *key++
        xchg    x2,ax                   ; x1 += x2
        mov     dx,x1
        call    MulMod
        add     x2,ax                   ; x1 *= *key++
        xchg    x1,ax                   ; x2 += x1

        xor     x0,x1                   ; x0 ^= x1
        xor     x3,x2                   ; x3 ^= x2
        pop     dx
        pop     ax
        xor     x1,dx                   ; x1 ^= s1
        xor     x2,ax                   ; x2 ^= s0

        mov     dx,x0
        dec     byte ptr [Rounds]       ; Continue until no more rounds
        jnz     Round

        call    MulMod
        xchg    x0,ax                   ; x0 *= *key++
        lodsw
        add     x2,ax                   ; x2 += *key++
        lodsw
        add     x1,ax                   ; x1 += *key++
        mov     dx,x3
        call    MulMod                  ; x3 *= *key++

        pop     di
        push    di

        xchg    x0,ax
        stosw
        xchg    x2,ax                   ; unswap x1, x2
        stosw
        xchg    x1,ax
        stosw
        xchg    x0,ax
        stosw

        pop     di
        ret

; Multiplication modulo 65537
; ax = [si] * dx

MulMod:
        push    dx
        lodsw
        mul     dx
        sub     ax,dx
        pop     dx
        jnz     NotZero
        inc     ax
        sub     ax,word ptr [si-2]
        sub     ax,dx
        ret
NotZero:
        adc     ax,0
        ret

; Data used by main program

Message:
        db      "Error",9

Usage:
        db      "IDEA � File",36

EnterKey:
        db      "Key: ",36

Password:
        db      PassLen,?

Passphrase:
        db      PassLen dup (?)

; Data used by IDEA routine

Rounds:
        db      ?

        db      ?                       ; Comment out if assembly inserts NOP
        even

; Data used by Tandem DM hashing routine

Key:
        dw      8 dup (?)
w_val:
        dw      4 dup (?)
g0:
        dw      4 dup (?)
hashKey:
        dw      52 dup (?)

; Data used by CFB routine

CFBBuffer:
        db      8 dup (?)

; Data buffer

Buffer:
        db      BuffLen dup (?)

        end     Start

