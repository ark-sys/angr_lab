import angr
import claripy

def main(bin = './task_6'):
    # Create an Angr project.
    project = angr.Project(bin)

    # start at the beginning of task6

    entry_point=0x401444
    initial_state = project.factory.blank_state(addr=entry_point)

    # initialize stack same as if we are running the function from the beginning
    initial_state.regs.rbp = initial_state.regs.rsp
    init_padding = 0x18
    initial_state.regs.rsp -= init_padding

    int1=claripy.BVS('int1',32*6)

    initial_state.stack_push(int1)

    # Create a simulation manager initialized with the starting state. It provides
    # a number of useful tools to search and execute the binary.
    simulation = project.factory.simgr(initial_state)

    # Avoid all states that can potentially print an error message
    avoid_addr=[0x401497,0x40144C]
    # Make sure to pass from these addresses which are located just after the error message
    find_addr=[0x4014CC]

    simulation.explore(find=find_addr, avoid=avoid_addr)

    # Check that we have found a solution. The simulation.explore() method will
    # set simulation.found to a list of the states that it could find that reach
    # the instruction we asked it to search for. Remember, in Python, if a list
    # is empty, it will be evaluated as false, otherwise true.
    if simulation.found:
        # Just take the first found solution
        solution_state = simulation.found[0]

        for _ in range(3):
            # pop last byte from stack, here we will find two integers
            pop_int = solution_state.solver.eval(solution_state.stack_pop())
            print(pop_int & 0xffffffff)
            print(pop_int>>32 & 0xffffffff)
    else:
        # If Angr could not find a path that reaches print_good_address, throw an
        # error. Perhaps you mistyped the print_good_address?
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main()
