; =====================================================================
;  TAMPER_SIMULATOR.ASM - demo "attacker" used to test the Sentinel
;  against our own Victim_Target. Writes one DWORD into a process.
; =====================================================================

INCLUDE Irvine32.inc
INCLUDE Macros.inc

OpenProcess        PROTO, dwAccess:DWORD, bInherit:DWORD, dwPid:DWORD
WriteProcessMemory PROTO, hProc:DWORD, lpBase:DWORD, lpBuf:PTR BYTE, nSize:DWORD, lpWritten:PTR DWORD

.data
tgtPid   DWORD ?
tgtAddr  DWORD ?
newVal   DWORD ?
hP       DWORD ?
written  DWORD ?

.code
main PROC
    mWrite "TAMPER SIMULATOR (demo only)"
    call Crlf
    mWrite "Target PID (decimal)  : "
    call ReadDec
    mov  tgtPid, eax
    mWrite "Address (hex)         : "
    call ReadHex
    mov  tgtAddr, eax
    mWrite "New DWORD value (hex) : "
    call ReadHex
    mov  newVal, eax

    INVOKE OpenProcess, 38h, 0, tgtPid      ; VM_WRITE | VM_OPERATION | VM_READ
    mov  hP, eax
    test eax, eax
    jz   fail
    INVOKE WriteProcessMemory, hP, tgtAddr, ADDR newVal, 4, ADDR written
    test eax, eax
    jz   fail
    mWrite "Wrote 4 bytes."
    call Crlf
    INVOKE CloseHandle, hP
    jmp  done
fail:
    mWrite "Operation failed, GetLastError = "
    INVOKE GetLastError
    call WriteDec
    call Crlf
done:
    call WaitMsg
    INVOKE ExitProcess, 0
main ENDP
END main
