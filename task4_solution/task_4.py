import sys
import angr
import claripy

def main(bin = './task_4'):
    # Create an Angr project.
    project = angr.Project(bin)

    # Prepare arguments in order to reproduce the effect of scanf(%8s %8s %8s %8s)
    arg1 = claripy.BVS('arg1', 8*8)
    arg2 = claripy.BVS('arg2', 8*8)


    # start one instruction after the call to scanf
    entry_point = 0x40131c
    initial_state = project.factory.blank_state(addr=entry_point)

    # User input is stored at this address (from disassemble)
    user_input_mem_0 = 0x404070
    user_input_mem_1 = 0x404078
    heap_addr_0 = 0xFFFF7777
    heap_addr_1 = 0xFFFF7797

    initial_state.memory.store(user_input_mem_0, heap_addr_0, endness=project.arch.memory_endness)
    initial_state.memory.store(user_input_mem_1, heap_addr_1, endness=project.arch.memory_endness)

    initial_state.memory.store(heap_addr_0, arg1)
    initial_state.memory.store(heap_addr_1, arg2)


    # add constraints to each word, we already know that we are looking for an 8 characters long word with all capital letters
    for i in range(8):
        initial_state.solver.add(arg1.get_byte(i) >= chr(65))
        initial_state.solver.add(arg1.get_byte(i) <= chr(90))
    for i in range(8):
        initial_state.solver.add(arg2.get_byte(i) >= chr(65))
        initial_state.solver.add(arg2.get_byte(i) <= chr(90))


    # Create a simulation manager initialized with the starting state. It provides
    # a number of useful tools to search and execute the binary.
    simulation = project.factory.simgr(initial_state)

    find_addr=0x4013EA
    # Explore the binary to attempt to find the address that prints "Good job!"
    # You will have to find the address you want to find and insert it here.
    # This function will keep executing until it either finds a solution or it
    # has explored every possible path through the executable.
    simulation.explore(find=find_addr)

    # Check that we have found a solution. The simulation.explore() method will
    # set simulation.found to a list of the states that it could find that reach
    # the instruction we asked it to search for. Remember, in Python, if a list
    # is empty, it will be evaluated as false, otherwise true.
    if simulation.found:
        # Just take the first found solution
        solution_state = simulation.found[0]

        # Print the string that Angr wrote to stdin; this is our solution.
        solution0 = solution_state.solver.eval(arg1, cast_to=bytes)
        solution1 = solution_state.solver.eval(arg2, cast_to=bytes)


        print(solution0, solution1)

    else:
        # If Angr could not find a path that reaches print_good_address, throw an
        # error. Perhaps you mistyped the print_good_address?
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main()
