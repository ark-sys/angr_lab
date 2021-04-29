# ANSWERS

## task5 :

> As usual, some helpful data with ``strings``

    giants
    isrveawhobpnutfg
    Enter the password:
    %6s %6s << interesting

> Also in this binary multiple functions are called, here is an overview from IDA Pro
> 
> This time there is no success message, so I'll try to avoid the error message
> 
> What's also interesting is the use of the functions **str_len** and **str_eq** which seem to behave the same as **strlen** and **strncmp**
> 
> So I've put two hooks for these two functions, added constraints for the input (we are looking for 12 small letters)
> 
> And the found flag is ``oaekmaobekma``
