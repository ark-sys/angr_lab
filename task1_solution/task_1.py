import sys
import angr

def main(argv):
    # Create an Angr project.
    project = angr.Project('task_1')

    # Tell Angr where to start executing (should it start from the main()
    # function or somewhere else?) In Challenge 1, use the entry_state
    # function to instruct Angr to start from the main() function.
    initial_state = project.factory.entry_state()

    # Create a simulation manager initialized with the starting state. It provides
    # a number of useful tools to search and execute the binary.
    simulation = project.factory.simgr(initial_state)

    # Explore the binary to attempt to find the address that prints "Password OK!"
    # You will have to find the address you want to find and insert it here.
    # This function will keep executing until it either finds a solution or it
    # has explored every possible path through the executable.
    print_good_address = 0x401229
    simulation.explore(find=print_good_address)

    # Check that we have found a solution. The simulation.explore() method will
    # set simulation.found to a list of the states that it could find that reach
    # the instruction we asked it to search for. Remember, in Python, if a list
    # is empty, it will be evaluated as false, otherwise true.
    if simulation.found:
        # Just take the first found solution
        solution_state = simulation.found[0]

        # Print the string that Angr wrote to stdin; this is our solution.
        print(solution_state.posix.dumps(sys.stdin.fileno()))

    else:
        # If Angr could not find a path that reaches print_good_address, throw an
        # error. Perhaps you mistyped the print_good_address?
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main(sys.argv)
