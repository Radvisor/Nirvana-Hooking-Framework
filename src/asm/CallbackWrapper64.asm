; LowCallbackWrapper64.asm
; Assemble with: ml64 /Fo LowCallbackWrapper64.obj /c LowCallbackWrapper64.asm

OPTION DOTNAME
OPTION CASEMAP:NONE

; Nom manglé fictif — à corriger selon le dump du symbole réel
extern ?HighCallbackWrapper@NirvanaHookingTable@@QEAAX_K_K_K_K_K_K@Z : proc

.code
LowCallbackWrapper64 PROC
    ; Sauvegarder les registres volatiles
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11

    ; Shadow space requis par convention x64 Windows
    sub rsp, 20h

    ; rcx = this
    mov rcx, 0DEADBEEFDEADBEEFh   ; <-- À remplacer par l'adresse réelle de l'instance

    ; rdx = rcx original (1er argument syscall)
    mov rdx, rcx

    ; r8 = rdx original (2e argument syscall)
    mov r8, rdx

    ; r9 = r8 original (3e argument syscall)
    mov r9, r8

    ; r10 = adresse de l’appelant → à empiler manuellement si nécessaire
    ; Tu peux le passer comme 5e paramètre si ta fonction le prend via la stack :
    ; mov [rsp + 20h], r10

    ; Appel de la méthode
    call ?HighCallbackWrapper@NirvanaHookingTable@@QEAAX_K_K_K_K_K_K@Z

    ; Restaurer la stack
    add rsp, 20h

    ; Restaurer les registres volatiles
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax

    ret
LowCallbackWrapper64 ENDP
END