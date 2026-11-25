; =====================================================================
;  AEGIS32 :: DYNAMIC MEMORY SENTINEL
;  Real-time x86 memory integrity scanner (MASM + Irvine32 + Win32 API)
;
;  Pipeline
;   1. Toolhelp32 snapshot  -> enumerate processes, keep 32-bit targets
;   2. OpenProcess          -> attach with least privilege (VM_READ)
;   3. VirtualQueryEx walk  -> map every committed, executable image
;                              region (the target's code sections)
;   4. ReadProcessMemory    -> hash every 4 KB page (FNV-1a, 32-bit)
;                              and keep a byte-exact baseline copy
;   5. Real-time loop       -> re-hash, compare, raise alerts:
;        - CODE PAGE TAMPERED  (with exact byte-level forensic diff)
;        - PROTECTION CHANGE   (e.g. VirtualProtectEx to RWX)
;        - GUARDED VALUE CHANGED via a multi-level pointer chain that
;          is RE-RESOLVED every cycle (module base + offsets), so it
;          survives ASLR and heap relocation
;        - page RESTORED, target relocation, target exit
; =====================================================================

INCLUDE Irvine32.inc
INCLUDE Macros.inc
INCLUDELIB kernel32.lib

; ---------------------------------------------------------------------
;  Constants
; ---------------------------------------------------------------------
AG_SNAP_PROC     equ 00000002h        ; TH32CS_SNAPPROCESS
AG_SNAP_MOD      equ 00000018h        ; TH32CS_SNAPMODULE | SNAPMODULE32
AG_PROC_LIMITED  equ 00001000h        ; PROCESS_QUERY_LIMITED_INFORMATION
AG_ACCESS        equ 00000410h        ; QUERY_INFORMATION | VM_READ
AG_MEM_COMMIT    equ 00001000h
AG_MEM_IMAGE     equ 01000000h
AG_EXEC_MASK     equ 000000F0h        ; any PAGE_EXECUTE_* flavour
AG_PAGE_GUARD    equ 00000100h
AG_STILL_ACTIVE  equ 259
AG_BADH          equ 0FFFFFFFFh       ; INVALID_HANDLE_VALUE
AG_USER_LIMIT    equ 0FFFE0000h
AG_PAGE          equ 4096
AG_MAX_REGIONS   equ 128
AG_MAX_PAGES     equ 2048             ; 8 MB of protected code
AG_MAX_CHAIN     equ 6

; ---------------------------------------------------------------------
;  Win32 structures (32-bit layouts, ANSI)
; ---------------------------------------------------------------------
AG_PE32 STRUCT                        ; PROCESSENTRY32
    peSize      DWORD   ?
    peUsage     DWORD   ?
    pePid       DWORD   ?
    peHeap      DWORD   ?
    peModId     DWORD   ?
    peThreads   DWORD   ?
    pePpid      DWORD   ?
    pePriBase   SDWORD  ?
    peFlags     DWORD   ?
    peExe       BYTE    260 DUP(?)
AG_PE32 ENDS

AG_ME32 STRUCT                        ; MODULEENTRY32
    meSize      DWORD   ?
    meModId     DWORD   ?
    mePid       DWORD   ?
    meGlbl      DWORD   ?
    mePcnt      DWORD   ?
    meBase      DWORD   ?
    meBaseSz    DWORD   ?
    meHandle    DWORD   ?
    meName      BYTE    256 DUP(?)
    mePath      BYTE    260 DUP(?)
AG_ME32 ENDS

AG_MBI STRUCT                         ; MEMORY_BASIC_INFORMATION
    mbBase      DWORD   ?
    mbAllocBase DWORD   ?
    mbAllocProt DWORD   ?
    mbSize      DWORD   ?
    mbState     DWORD   ?
    mbProt      DWORD   ?
    mbType      DWORD   ?
AG_MBI ENDS

REGION STRUCT                         ; one monitored code region
    rgBase      DWORD   ?
    rgSize      DWORD   ?
    rgProt      DWORD   ?
    rgPageStart DWORD   ?             ; index into global page tables
    rgPageCnt   DWORD   ?
    rgFlag      DWORD   ?             ; protection-alert latch
REGION ENDS

; ---------------------------------------------------------------------
;  Win32 prototypes not already provided by SmallWin.inc
;  (if the assembler reports a redefinition, delete that PROTO line)
; ---------------------------------------------------------------------
CreateToolhelp32Snapshot PROTO, dwFlags:DWORD, th32Pid:DWORD
Process32First     PROTO, hSnap:DWORD, lppe:PTR AG_PE32
Process32Next      PROTO, hSnap:DWORD, lppe:PTR AG_PE32
Module32First      PROTO, hSnap:DWORD, lpme:PTR AG_ME32
OpenProcess        PROTO, dwAccess:DWORD, bInherit:DWORD, dwPid:DWORD
ReadProcessMemory  PROTO, hProc:DWORD, lpBase:DWORD, lpBuf:PTR BYTE, nSize:DWORD, lpRead:PTR DWORD
VirtualQueryEx     PROTO, hProc:DWORD, lpAddr:DWORD, lpBuf:PTR AG_MBI, dwLen:DWORD
IsWow64Process     PROTO, hProc:DWORD, pWow64:PTR DWORD
GetExitCodeProcess PROTO, hProc:DWORD, pExit:PTR DWORD

; ---------------------------------------------------------------------
;  Small helper macro: set console colour without touching EAX
; ---------------------------------------------------------------------
SetColor MACRO c
    push eax
    mov  eax, c
    call SetTextColor
    pop  eax
ENDM

; =====================================================================
.data
bn1  BYTE "    _    _____ ____ ___ ____  _________ ",0Dh,0Ah,0
bn2  BYTE "   / \  | ____/ ___|_ _/ ___||___ /___ \",0Dh,0Ah,0
bn3  BYTE "  / _ \ |  _|| |  _ | |\___ \  |_ \ __) |",0Dh,0Ah,0
bn4  BYTE " / ___ \| |__| |_| || | ___) |___) / __/",0Dh,0Ah,0
bn5  BYTE "/_/   \_\_____\____|___|____/|____/_____|",0Dh,0Ah,0
bn6  BYTE "      D Y N A M I C   M E M O R Y   S E N T I N E L",0Dh,0Ah,0
bn7  BYTE "      x86 MASM | Irvine32 | Win32 API | real-time integrity monitor",0Dh,0Ah,0Dh,0Ah,0

targetPid       DWORD 0
hProc           DWORD 0
modBase         DWORD 0
interval        DWORD 250
cycles          DWORD 0
lastScanMs      DWORD 0
totalAlerts     DWORD 0
startMs         DWORD 0
t0              DWORD 0
exitCode        DWORD 0
regionCount     DWORD 0
pageTotal       DWORD 0
truncated       DWORD 0
tmpIdx          DWORD 0

chainEnabled    DWORD 0
chainBaseOff    DWORD 0
chainDepth      DWORD 0
chainOffs       DWORD AG_MAX_CHAIN DUP(0)
chainHaveLast   DWORD 0
chainLastAddr   DWORD 0
chainLastVal    DWORD 0
chainBroken     DWORD 0

.data?
regionTable     REGION AG_MAX_REGIONS DUP(<>)
pageHashes      DWORD  AG_MAX_PAGES DUP(?)
pageFlags       BYTE   AG_MAX_PAGES DUP(?)
pageBuf         BYTE   AG_PAGE DUP(?)
baselineImg     BYTE   AG_MAX_PAGES * AG_PAGE DUP(?)

; =====================================================================
.code

; ---------------------------------------------------------------------
;  HashPage : read one page from the target, return FNV-1a hash in EAX
;             (EAX = 0 when the page cannot be read). Page bytes are
;             left in pageBuf for forensic diffing.
; ---------------------------------------------------------------------
HashPage PROC USES ebx esi, hP:DWORD, pVA:DWORD
    LOCAL got:DWORD
    mov  got, 0
    INVOKE ReadProcessMemory, hP, pVA, OFFSET pageBuf, AG_PAGE, ADDR got
    test eax, eax
    jz   hpFail
    cmp  got, AG_PAGE
    jne  hpFail
    mov  esi, OFFSET pageBuf
    mov  ecx, AG_PAGE
    mov  eax, 811C9DC5h               ; FNV offset basis
hpLoop:
    movzx ebx, BYTE PTR [esi]
    xor  eax, ebx
    imul eax, eax, 01000193h          ; FNV prime
    inc  esi
    dec  ecx
    jnz  hpLoop
    ret
hpFail:
    xor  eax, eax
    ret
HashPage ENDP

; ---------------------------------------------------------------------
;  ResolveChain : dynamic pointer resolution (Cheat-Engine style path)
;     cur = start
;     repeat count times:  cur = [cur] + offsets[i]
;  EAX = 1 on success (final address stored in *pOut), 0 on failure
; ---------------------------------------------------------------------
ResolveChain PROC USES ebx esi, hP:DWORD, startAddr:DWORD, pOffs:DWORD, count:DWORD, pOut:DWORD
    LOCAL cur:DWORD, tmp:DWORD, got:DWORD
    mov  eax, startAddr
    mov  cur, eax
    mov  esi, pOffs
    mov  ebx, count
rcLoop:
    test ebx, ebx
    jz   rcDone
    mov  tmp, 0
    mov  got, 0
    INVOKE ReadProcessMemory, hP, cur, ADDR tmp, 4, ADDR got
    test eax, eax
    jz   rcFail
    cmp  got, 4
    jne  rcFail
    mov  eax, tmp
    test eax, eax                     ; null pointer in the chain
    jz   rcFail
    add  eax, [esi]
    mov  cur, eax
    add  esi, 4
    dec  ebx
    jmp  rcLoop
rcDone:
    mov  edx, pOut
    mov  eax, cur
    mov  [edx], eax
    mov  eax, 1
    ret
rcFail:
    xor  eax, eax
    ret
ResolveChain ENDP

; ---------------------------------------------------------------------
;  GetMainModuleBase : base address of the target's EXE (EAX, 0 = fail)
; ---------------------------------------------------------------------
GetMainModuleBase PROC USES ebx, pid:DWORD
    LOCAL hSnap:DWORD, me:AG_ME32
    INVOKE CreateToolhelp32Snapshot, AG_SNAP_MOD, pid
    mov  hSnap, eax
    cmp  eax, AG_BADH
    je   gmFail
    mov  me.meSize, SIZEOF AG_ME32
    xor  ebx, ebx
    INVOKE Module32First, hSnap, ADDR me
    test eax, eax
    jz   gmClose
    mov  ebx, me.meBase
gmClose:
    INVOKE CloseHandle, hSnap
    mov  eax, ebx
    ret
gmFail:
    xor  eax, eax
    ret
GetMainModuleBase ENDP

; ---------------------------------------------------------------------
;  ReportDiff : byte-level forensic diff between baseline and live page
;               (live bytes are in pageBuf from the last HashPage)
; ---------------------------------------------------------------------
ReportDiff PROC USES eax ebx ecx esi edi, pageVA:DWORD, pOld:DWORD
    LOCAL shown:DWORD, total:DWORD
    mov  shown, 0
    mov  total, 0
    mov  esi, OFFSET pageBuf
    mov  edi, pOld
    xor  ecx, ecx
rdLoop:
    mov  al, [esi+ecx]
    cmp  al, [edi+ecx]
    je   rdNext
    inc  total
    cmp  shown, 4                     ; print at most 4 detailed bytes
    jae  rdNext
    inc  shown
    mWrite "      byte @ "
    mov  eax, pageVA
    add  eax, ecx
    call WriteHex
    mWrite "   original "
    movzx eax, BYTE PTR [edi+ecx]
    mov  ebx, 1
    call WriteHexB
    mWrite "   now "
    movzx eax, BYTE PTR [esi+ecx]
    mov  ebx, 1
    call WriteHexB
    call Crlf
rdNext:
    inc  ecx
    cmp  ecx, AG_PAGE
    jb   rdLoop
    mWrite "      modified bytes in this page: "
    mov  eax, total
    call WriteDec
    call Crlf
    ret
ReportDiff ENDP

; ---------------------------------------------------------------------
;  BuildBaseline : walk the address space with VirtualQueryEx, register
;  every committed executable image region, hash + snapshot its pages.
; ---------------------------------------------------------------------
BuildBaseline PROC USES ebx esi edi, hP:DWORD
    LOCAL mbi:AG_MBI, cur:DWORD, pages:DWORD
    mov  cur, 0
    mov  regionCount, 0
    mov  pageTotal, 0
    mov  truncated, 0
bbNext:
    cmp  cur, AG_USER_LIMIT
    jae  bbDone
    INVOKE VirtualQueryEx, hP, cur, ADDR mbi, SIZEOF AG_MBI
    test eax, eax
    jz   bbDone
    cmp  mbi.mbState, AG_MEM_COMMIT
    jne  bbAdvance
    cmp  mbi.mbType, AG_MEM_IMAGE
    jne  bbAdvance
    test mbi.mbProt, AG_EXEC_MASK
    jz   bbAdvance
    test mbi.mbProt, AG_PAGE_GUARD
    jnz  bbAdvance
    cmp  regionCount, AG_MAX_REGIONS
    jae  bbNoRoom
    mov  eax, mbi.mbSize
    shr  eax, 12
    mov  pages, eax
    mov  edx, AG_MAX_PAGES
    sub  edx, pageTotal
    jbe  bbNoRoom
    cmp  eax, edx
    jbe  bbFits
    mov  pages, edx
    mov  truncated, 1
bbFits:
    mov  eax, regionCount
    imul eax, SIZEOF REGION
    lea  edi, regionTable[eax]
    ASSUME edi:PTR REGION
    mov  eax, mbi.mbBase
    mov  [edi].rgBase, eax
    mov  eax, mbi.mbSize
    mov  [edi].rgSize, eax
    mov  eax, mbi.mbProt
    mov  [edi].rgProt, eax
    mov  eax, pageTotal
    mov  [edi].rgPageStart, eax
    mov  eax, pages
    mov  [edi].rgPageCnt, eax
    mov  [edi].rgFlag, 0
    ASSUME edi:NOTHING
    xor  ebx, ebx
bbPage:
    cmp  ebx, pages
    jae  bbPagesDone
    mov  eax, ebx
    shl  eax, 12
    add  eax, mbi.mbBase
    INVOKE HashPage, hP, eax
    mov  edx, pageTotal
    add  edx, ebx
    mov  pageHashes[edx*4], eax
    mov  pageFlags[edx], 0
    shl  edx, 12
    lea  edi, baselineImg[edx]
    mov  esi, OFFSET pageBuf
    mov  ecx, AG_PAGE / 4
    cld
    rep  movsd
    inc  ebx
    jmp  bbPage
bbPagesDone:
    mov  eax, pages
    add  pageTotal, eax
    inc  regionCount
    jmp  bbAdvance
bbNoRoom:
    mov  truncated, 1
    jmp  bbDone
bbAdvance:
    mov  eax, mbi.mbBase
    add  eax, mbi.mbSize
    jc   bbDone
    cmp  eax, cur
    jbe  bbDone
    mov  cur, eax
    jmp  bbNext
bbDone:
    mov  eax, regionCount
    ret
BuildBaseline ENDP

; ---------------------------------------------------------------------
;  ScanBaseline : one full verification sweep. Returns new alert count.
; ---------------------------------------------------------------------
ScanBaseline PROC USES ebx esi edi, hP:DWORD
    LOCAL mbi:AG_MBI, rIdx:DWORD, pIdx:DWORD, curHash:DWORD, newAlerts:DWORD, pageVA:DWORD
    mov  newAlerts, 0
    mov  rIdx, 0
sbRegion:
    mov  eax, rIdx
    cmp  eax, regionCount
    jae  sbDone
    imul eax, SIZEOF REGION
    lea  esi, regionTable[eax]
    ASSUME esi:PTR REGION

    ; ---- audit page protection of the region -------------------------
    mov  edx, [esi].rgBase
    INVOKE VirtualQueryEx, hP, edx, ADDR mbi, SIZEOF AG_MBI
    test eax, eax
    jz   sbPages
    mov  eax, mbi.mbProt
    cmp  eax, [esi].rgProt
    jne  sbProtDiff
    mov  [esi].rgFlag, 0
    jmp  sbPages
sbProtDiff:
    cmp  [esi].rgFlag, 0
    jne  sbPages
    mov  [esi].rgFlag, 1
    inc  newAlerts
    inc  totalAlerts
    call Crlf
    SetColor lightRed
    mWrite "[ALERT] PROTECTION CHANGE  region "
    mov  eax, [esi].rgBase
    call WriteHex
    mWrite "  was "
    mov  eax, [esi].rgProt
    call WriteHex
    mWrite "  now "
    mov  eax, mbi.mbProt
    call WriteHex
    call Crlf
    SetColor lightGray

    ; ---- verify every page ------------------------------------------
sbPages:
    mov  pIdx, 0
sbPageLoop:
    mov  eax, pIdx
    cmp  eax, [esi].rgPageCnt
    jae  sbNextRegion
    shl  eax, 12
    add  eax, [esi].rgBase
    mov  pageVA, eax
    INVOKE HashPage, hP, pageVA
    mov  curHash, eax
    mov  ebx, [esi].rgPageStart
    add  ebx, pIdx                    ; EBX = global page index
    mov  eax, pageHashes[ebx*4]
    cmp  eax, curHash
    je   sbMatch

    cmp  pageFlags[ebx], 0            ; already reported?
    jne  sbPageNext
    mov  pageFlags[ebx], 1
    inc  newAlerts
    inc  totalAlerts
    call Crlf
    SetColor lightRed
    mWrite "[ALERT] CODE PAGE TAMPERED  va="
    mov  eax, pageVA
    call WriteHex
    mWrite "  hash "
    mov  eax, pageHashes[ebx*4]
    call WriteHex
    mWrite " now "
    mov  eax, curHash
    call WriteHex
    call Crlf
    SetColor yellow
    cmp  curHash, 0
    je   sbUnread
    mov  eax, ebx
    shl  eax, 12
    add  eax, OFFSET baselineImg
    INVOKE ReportDiff, pageVA, eax
    jmp  sbAfterDiff
sbUnread:
    mWrite "      page unreadable or unmapped"
    call Crlf
sbAfterDiff:
    SetColor lightGray
    jmp  sbPageNext

sbMatch:
    cmp  pageFlags[ebx], 0
    je   sbPageNext
    mov  pageFlags[ebx], 0
    call Crlf
    SetColor lightGreen
    mWrite "[ OK  ] page restored to baseline  va="
    mov  eax, pageVA
    call WriteHex
    call Crlf
    SetColor lightGray
sbPageNext:
    inc  pIdx
    jmp  sbPageLoop
sbNextRegion:
    inc  rIdx
    jmp  sbRegion
sbDone:
    ASSUME esi:NOTHING
    mov  eax, newAlerts
    ret
ScanBaseline ENDP

; ---------------------------------------------------------------------
;  GuardPointer : re-resolve the pointer chain every cycle and watch the
;                 final value. Handles relocation of the target object.
; ---------------------------------------------------------------------
GuardPointer PROC USES ebx, hP:DWORD, pMod:DWORD
    LOCAL fin:DWORD, val:DWORD, got:DWORD, alerts:DWORD
    mov  alerts, 0
    mov  edx, pMod
    add  edx, chainBaseOff
    INVOKE ResolveChain, hP, edx, OFFSET chainOffs, chainDepth, ADDR fin
    test eax, eax
    jnz  gpOk
    cmp  chainBroken, 0
    jne  gpRet
    mov  chainBroken, 1
    call Crlf
    SetColor yellow
    mWrite "[WARN ] pointer chain unresolved (object freed or moved)"
    call Crlf
    SetColor lightGray
    jmp  gpRet
gpOk:
    mov  chainBroken, 0
    mov  val, 0
    mov  got, 0
    INVOKE ReadProcessMemory, hP, fin, ADDR val, 4, ADDR got
    test eax, eax
    jz   gpRet
    cmp  chainHaveLast, 0
    jne  gpCompare
    mov  chainHaveLast, 1
    mov  eax, fin
    mov  chainLastAddr, eax
    mov  eax, val
    mov  chainLastVal, eax
    call Crlf
    SetColor lightGreen
    mWrite "[ PTR ] chain resolved: target address "
    mov  eax, fin
    call WriteHex
    mWrite "  value "
    mov  eax, val
    call WriteDec
    call Crlf
    SetColor lightGray
    jmp  gpRet
gpCompare:
    mov  eax, fin
    cmp  eax, chainLastAddr
    je   gpSameAddr
    call Crlf
    SetColor yellow
    mWrite "[ PTR ] target relocated: "
    mov  eax, chainLastAddr
    call WriteHex
    mWrite " to "
    mov  eax, fin
    call WriteHex
    call Crlf
    SetColor lightGray
    mov  eax, fin
    mov  chainLastAddr, eax
gpSameAddr:
    mov  eax, val
    cmp  eax, chainLastVal
    je   gpRet
    inc  totalAlerts
    mov  alerts, 1
    call Crlf
    SetColor lightRed
    mWrite "[ALERT] GUARDED VALUE CHANGED at "
    mov  eax, fin
    call WriteHex
    mWrite "  old "
    mov  eax, chainLastVal
    call WriteDec
    mWrite "  new "
    mov  eax, val
    call WriteDec
    call Crlf
    SetColor lightGray
    mov  eax, val
    mov  chainLastVal, eax
gpRet:
    mov  eax, alerts
    ret
GuardPointer ENDP

; ---------------------------------------------------------------------
;  ListProcesses : print only 32-bit (WOW64) processes we can open
; ---------------------------------------------------------------------
ListProcesses PROC USES ebx esi
    LOCAL hSnap:DWORD, pe:AG_PE32, hP:DWORD, wow:DWORD, shown:DWORD
    mov  shown, 0
    INVOKE CreateToolhelp32Snapshot, AG_SNAP_PROC, 0
    mov  hSnap, eax
    cmp  eax, AG_BADH
    je   lpDone
    mov  pe.peSize, SIZEOF AG_PE32
    INVOKE Process32First, hSnap, ADDR pe
lpLoop:
    test eax, eax
    jz   lpClose
    mov  wow, 0
    INVOKE OpenProcess, AG_PROC_LIMITED, 0, pe.pePid
    mov  hP, eax
    test eax, eax
    jz   lpNext
    INVOKE IsWow64Process, hP, ADDR wow
    INVOKE CloseHandle, hP
    cmp  wow, 0
    je   lpNext
    inc  shown
    SetColor lightGreen
    mov  eax, pe.pePid
    call WriteDec
    mov  al, 9
    call WriteChar
    SetColor lightGray
    lea  edx, pe.peExe
    call WriteString
    call Crlf
lpNext:
    INVOKE Process32Next, hSnap, ADDR pe
    jmp  lpLoop
lpClose:
    INVOKE CloseHandle, hSnap
lpDone:
    SetColor lightGray
    cmp  shown, 0
    jne  lpRet
    mWrite "  (no 32-bit processes found - start the target first)"
    call Crlf
lpRet:
    ret
ListProcesses ENDP

; ---------------------------------------------------------------------
;  PrintRegions : table of monitored regions
; ---------------------------------------------------------------------
PrintRegions PROC USES eax ebx esi
    xor  ebx, ebx
prLoop:
    cmp  ebx, regionCount
    jae  prDone
    mov  eax, ebx
    imul eax, SIZEOF REGION
    lea  esi, regionTable[eax]
    ASSUME esi:PTR REGION
    mWrite "  region #"
    mov  eax, ebx
    call WriteDec
    mWrite "   base "
    mov  eax, [esi].rgBase
    call WriteHex
    mWrite "   size "
    mov  eax, [esi].rgSize
    call WriteHex
    mWrite "   prot "
    mov  eax, [esi].rgProt
    call WriteHex
    call Crlf
    inc  ebx
    jmp  prLoop
prDone:
    ASSUME esi:NOTHING
    ret
PrintRegions ENDP

; ---------------------------------------------------------------------
;  Banner / status line
; ---------------------------------------------------------------------
Banner PROC USES eax edx
    SetColor lightCyan
    mov  edx, OFFSET bn1
    call WriteString
    mov  edx, OFFSET bn2
    call WriteString
    mov  edx, OFFSET bn3
    call WriteString
    mov  edx, OFFSET bn4
    call WriteString
    mov  edx, OFFSET bn5
    call WriteString
    SetColor white
    mov  edx, OFFSET bn6
    call WriteString
    SetColor gray
    mov  edx, OFFSET bn7
    call WriteString
    SetColor lightGray
    ret
Banner ENDP

DrawStatus PROC USES eax
    mov  al, 0Dh
    call WriteChar
    SetColor lightCyan
    mWrite "[SENTINEL] cycle "
    mov  eax, cycles
    call WriteDec
    mWrite " | pages "
    mov  eax, pageTotal
    call WriteDec
    mWrite " | sweep "
    mov  eax, lastScanMs
    call WriteDec
    mWrite " ms | alerts "
    cmp  totalAlerts, 0
    jne  dsRed
    SetColor lightGreen
    jmp  dsPrint
dsRed:
    SetColor lightRed
dsPrint:
    mov  eax, totalAlerts
    call WriteDec
    SetColor gray
    mWrite "   (press Q to stop)      "
    SetColor lightGray
    ret
DrawStatus ENDP

; =====================================================================
main PROC
    call Clrscr
    call Banner
    SetColor white
    mWrite "Scannable 32-bit processes (PID / image):"
    call Crlf
    call ListProcesses
    call Crlf
    SetColor lightGray
    mWrite "Target PID (decimal): "
    call ReadDec
    mov  targetPid, eax

    INVOKE OpenProcess, AG_ACCESS, 0, targetPid
    mov  hProc, eax
    test eax, eax
    jnz  attached
    SetColor lightRed
    mWrite "OpenProcess failed, GetLastError = "
    INVOKE GetLastError
    call WriteDec
    call Crlf
    jmp  quit
attached:
    INVOKE GetMainModuleBase, targetPid
    mov  modBase, eax
    test eax, eax
    jnz  haveMod
    SetColor lightRed
    mWrite "Module enumeration failed (target must be a 32-bit process)."
    call Crlf
    jmp  quit
haveMod:
    SetColor lightGreen
    mWrite "Attached. Main module base = "
    mov  eax, modBase
    call WriteHex
    call Crlf
    SetColor lightGray

    ; ---- optional pointer-chain guard --------------------------------
    mWrite "Arm pointer-chain guard? (1 = yes, 0 = no): "
    call ReadDec
    mov  chainEnabled, eax
    cmp  eax, 1
    jne  noChain
    mWrite "  Root pointer offset from module base (hex): "
    call ReadHex
    mov  chainBaseOff, eax
    mWrite "  Chain depth (0-6): "
    call ReadDec
    cmp  eax, AG_MAX_CHAIN
    jbe  depthOk
    mov  eax, AG_MAX_CHAIN
depthOk:
    mov  chainDepth, eax
    mov  tmpIdx, 0
offLoop:
    mov  eax, tmpIdx
    cmp  eax, chainDepth
    jae  noChain
    mWrite "    offset #"
    mov  eax, tmpIdx
    call WriteDec
    mWrite " (hex): "
    call ReadHex
    mov  ecx, tmpIdx
    mov  chainOffs[ecx*4], eax
    inc  tmpIdx
    jmp  offLoop
noChain:
    mWrite "Scan interval in ms (0 = 250): "
    call ReadDec
    test eax, eax
    jz   keepInterval
    mov  interval, eax
keepInterval:

    ; ---- baseline -----------------------------------------------------
    call Crlf
    mWrite "Building baseline..."
    call Crlf
    INVOKE BuildBaseline, hProc
    call PrintRegions
    SetColor white
    mWrite "  protected pages: "
    mov  eax, pageTotal
    call WriteDec
    mWrite "  ("
    mov  eax, pageTotal
    shl  eax, 2
    call WriteDec
    mWrite " KB of code)"
    call Crlf
    cmp  truncated, 0
    je   noTrunc
    SetColor yellow
    mWrite "  note: image larger than table, coverage truncated"
    call Crlf
noTrunc:
    SetColor lightGreen
    mWrite "Sentinel ARMED. Monitoring in real time."
    call Crlf
    call Crlf
    SetColor lightGray
    call GetMseconds
    mov  startMs, eax

    ; ---- real-time monitoring loop ----------------------------------
monLoop:
    INVOKE GetExitCodeProcess, hProc, ADDR exitCode
    cmp  exitCode, AG_STILL_ACTIVE
    jne  targetGone
    call GetMseconds
    mov  t0, eax
    INVOKE ScanBaseline, hProc
    cmp  chainEnabled, 1
    jne  skipGuard
    INVOKE GetMainModuleBase, targetPid   ; re-resolved every cycle (ASLR safe)
    test eax, eax
    jz   skipGuard
    INVOKE GuardPointer, hProc, eax
skipGuard:
    inc  cycles
    call GetMseconds
    sub  eax, t0
    mov  lastScanMs, eax
    call DrawStatus
    call ReadKey
    jz   noKey
    or   al, 20h
    cmp  al, 'q'
    je   userStop
noKey:
    mov  eax, interval
    call Delay
    jmp  monLoop

targetGone:
    call Crlf
    SetColor yellow
    mWrite "Target process has exited."
    call Crlf
    jmp  report
userStop:
    call Crlf
report:
    SetColor white
    call Crlf
    mWrite "=========== SESSION REPORT ==========="
    call Crlf
    mWrite "  sweeps completed : "
    mov  eax, cycles
    call WriteDec
    call Crlf
    mWrite "  pages monitored  : "
    mov  eax, pageTotal
    call WriteDec
    call Crlf
    mWrite "  total alerts     : "
    mov  eax, totalAlerts
    call WriteDec
    call Crlf
    mWrite "  uptime (ms)      : "
    call GetMseconds
    sub  eax, startMs
    call WriteDec
    call Crlf
    INVOKE CloseHandle, hProc
quit:
    SetColor lightGray
    call Crlf
    call WaitMsg
    INVOKE ExitProcess, 0
main ENDP
END main
