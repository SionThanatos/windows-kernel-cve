_text segment

externdef  g_NtUserDefSetText_syscall:dword
externdef  g_NtUserMessageCall_syscall:dword

public NtUserMessageCall
NtUserMessageCall proc
    mov r10, rcx
    mov eax, g_NtUserMessageCall_syscall   
    syscall
    ret
NtUserMessageCall endp

public NtUserDefSetText
NtUserDefSetText proc
    mov r10, rcx
    mov eax, g_NtUserDefSetText_syscall
    syscall
    ret
NtUserDefSetText endp

_text ends
end
