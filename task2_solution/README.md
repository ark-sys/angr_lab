# ANSWERS

## task2 :

> First I've started fuzzing a little with the parameters of the program
>
> I've noticed that for different size of input, different messages are shown (let's keep that in mind for later)
> 
> An inspection of the disassembled binary didn't provide anything of interest (a lot of comparison and jumps are made, A LOT...) except that two parameters from the command line are loaded into %rsi
> 
> Also, argc is loaded in %edi and is used at address 0x401169 to check if we provided correctly 2 arguments 
> 
> So let's set up an ``angr`` script by importing the claripy module (it will be used to handle the two params)
>  
> During testing of the binary, i noticed that an odd number > 7 makes something interesting.
> 
> So i've created two symbolic bitvector or BVS, one for each argument
> 
> By doing `strings` on the program, we can dump the messages that are printed to the user. We notice here a message that is likely to be printed upon successful input of arguments.
> 
> The message is : **Abby & Gabby: yaayy!! nice job! :D**
> 
> By looking the program via IDA Pro we can also notice how the transition between blocks are made ![bin_ov](bin_overview.PNG)
> 
> The message we are looking for is called at address **0x4012C3** ![message](message_target.PNG)
> 
> So lets setup angr with these informations
> 
> At the first run of the program a solution is found, however the provided characters don't seem to work (the solver provided 0 0 as solution)
> 
> Since the parameters are provided from the command line and since the command line handles strings, here we need to add some constraints to the BVS so that angr will output only characters between 0 and 9
> 
> And voilà, the flag is ``00001111`` and ``00000000``