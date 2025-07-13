; LowCallbackWrapper32.asm
; Assemble with: ml /c /Fo LowCallbackWrapper32.obj LowCallbackWrapper32.asm

.386
.model flat, stdcall
option casemap:none

extern HighCallbackWrapper:proc

.code
LowCallbackWrapper32 PROC
    ; sauvegarder les registres
    push eax
    push ecx
    push edx
    push ebx
    push esi
    push edi
    push ebp

    sub esp, 20h

    ; mov ecx = this (car thiscall → ecx = this)
    mov ecx, 0DEADBEEFh

    ; push les autres arguments
    push 0BAADF00Dh ; <-- eip (adresse de l’appelant)
    push eax        ; <-- eax (valeur de retour syscall)

    call ?HighCallbackWrapper@NirvanaHookingTable@@QAEXII@Z

    add esp, 8      ; nettoyer les 2 paramètres (eax, eip)
    add esp, 20h

    pop ebp
    pop edi
    pop esi
    pop ebx
    pop edx
    pop ecx
    pop eax

    ret
LowCallbackWrapper32 ENDP
END