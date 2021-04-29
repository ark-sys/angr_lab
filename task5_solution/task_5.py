import sys
import angr
import claripy

def main(bin = './task_5'):
    # Create an Angr project.
    project = angr.Project(bin)

    # Prepare arguments in order to reproduce the effect of scanf(%6s %6s)
    arg1 = claripy.BVS('arg1', 8*6)
    arg2 = claripy.BVS('arg2', 8*6)

    str_len_addr=0x401283
    project.hook(str_len_addr, angr.SIM_PROCEDURES['libc']['strlen']())
    str_eq_addr=0x4011D6
    project.hook(str_eq_addr, angr.SIM_PROCEDURES['libc']['strncmp']())

    # start one instruction after the call to scanf
    entry_point = 0x40140b
    initial_state = project.factory.blank_state(addr=entry_point)
    user_input = 0x404067
    user_input_2 = 0x404060
    initial_state.memory.store(user_input, arg1)
    initial_state.memory.store(user_input_2, arg2)

    # add constraints to each word, we already know that we are looking for an 8 characters long word with all capital letters
    for i in range(6):
        initial_state.solver.add(arg1.get_byte(i) >= chr(97))
        initial_state.solver.add(arg1.get_byte(i) <= chr(122))
    for i in range(6):
        initial_state.solver.add(arg2.get_byte(i) >= chr(97))
        initial_state.solver.add(arg2.get_byte(i) <= chr(122))

    # Create a simulation manager initialized with the starting state. It provides
    # a number of useful tools to search and execute the binary.
    simulation = project.factory.simgr(initial_state)

    find_addr = [0x4013D1]
    avoid_addr = [0x40131F, 0x4013A6]
    simulation.explore(find=find_addr,avoid=avoid_addr)

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

        # print(solution0)
        print(solution0, solution1)

    else:
        # If Angr could not find a path that reaches print_good_address, throw an
        # error. Perhaps you mistyped the print_good_address?
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main()
