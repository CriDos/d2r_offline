option casemap:none

.code

X MACRO name:req, ordinal:req
    PUBLIC name
    EXTERN g_forward_&name:QWORD
name PROC
    jmp QWORD PTR [g_forward_&name]
name ENDP
ENDM

include exports_asm.inc

END
