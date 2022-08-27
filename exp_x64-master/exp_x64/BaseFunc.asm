.code

GetPEB proc
	mov rax, gs:[60h]
	ret
GetPEB endp

end