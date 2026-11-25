; =====================================================================
;  VICTIM_TARGET.ASM  -  harmless demo process for the Aegis32 Sentinel
;  Holds a "health" value behind a heap pointer and runs a tiny code
;  routine. Prints everything the Sentinel needs for the demo.
; =====================================================================

INCLUDE Irvine32.inc
INCLUDE Macros.inc

GetCurrentProcessId PROTO
GetModuleHandleA PROTO, lpModuleName:PTR BYTE

.data
gRoot   DWORD 0            ; root pointer  ->  heap object
tick    DWORD 0

.code
Heartbeat PROC
    nop                    ; 4 NOPs = safe patch target (write 41414141h)
    nop
    nop
    nop
    inc  tick
    ret
Heartbeat ENDP

main PROC
    INVOKE GetProcessHeap
    INVOKE HeapAlloc, eax, 8, 64            ; HEAP_ZERO_MEMORY
    mov  gRoot, eax
    mov  DWORD PTR [eax+10h], 100           ; object+0x10 = health

    mWrite "VICTIM  PID            : "
    INVOKE GetCurrentProcessId
    call WriteDec
    call Crlf

    mWrite "Module base            : "
    INVOKE GetModuleHandleA, 0
    mov  ebx, eax
    call WriteHex
    call Crlf

    mWrite "Root pointer offset    : "
    mov  eax, OFFSET gRoot
    sub  eax, ebx
    call WriteHex
    mWrite "   (chain depth 1, offset 10)"
    call Crlf

    mWrite "Health address         : "
    mov  eax, gRoot
    add  eax, 10h
    call WriteHex
    call Crlf

    mWrite "Heartbeat code address : "
    mov  eax, OFFSET Heartbeat
    call WriteHex
    call Crlf
    call Crlf

run:
    call Heartbeat
    mWrite "health = "
    mov  eax, gRoot
    mov  eax, [eax+10h]
    call WriteDec
    call Crlf
    mov  eax, 1000
    call Delay
    jmp  run
main ENDP
END main
