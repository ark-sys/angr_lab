# ANSWERS

## task1 :

> In order to solve the challenge, let's use ``angr`` and explore the path that leads to the `print` of the **success** message 
>
> I first dumped the code with ``objdump -d task_1`` and looked for the **main** function
> 
> By looking at the function, I noticed that a comparison occurs at address **0x401214** (a call to ``strcmp()`` is made)
> 
> The call of the function is followed by a 'result' check (at address **0x40121c**) -> ``if strcmp() == 0`` 
> 
> The result of this function indicates if its two string arguments are equal : in fact, our input is tested here! The password must be nearby...
> 
> At address **0x401220** a jump is taken to address **0x401230** if the two compared strings are not equal, so the address we are looking for must be in between
> 
> Indeed, at address **0x401229** a call to ``puts`` is made, this must be the good path!\
> 
> So after providing this address to, I could find the same flag as lab_4 : **250382**