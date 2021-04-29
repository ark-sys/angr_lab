import sys
import angr
import claripy

def main(bin = './task_2'):
    # Create an Angr project.
    project = angr.Project(bin)

    # Create a symbolic bitvector representing the parameters from the command line
    arg1 = claripy.BVS('arg1', 8*8)
    arg2 = claripy.BVS('arg2', 8*8)
    initial_state = project.factory.entry_state(args=[bin,arg1,arg2])

    # Add constraints on the arguments so that only integers are used
    for i in range(8):
        initial_state.add_constraints(arg1.get_byte(i) >= ord('0'))
        initial_state.add_constraints(arg1.get_byte(i) <= ord('9'))

    for i in range(8):
        initial_state.add_constraints(arg2.get_byte(i) >= ord('0'))
        initial_state.add_constraints(arg2.get_byte(i) <= ord('9'))
    # Create a simulation manager initialized with the starting state. It provides
    # a number of useful tools to search and execute the binary.
    simulation = project.factory.simgr(initial_state)

    # If the state that prints this message is found, then we have found the correct simulation
    def is_successful(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        if b'Abby & Gabby: yaayy!! nice job! :D' in stdout_output:
            return True
        else:
            return False

    # Explore simulations until the message is found
    simulation.explore(find=is_successful)

    # Check that we have found a solution. The simulation.explore() method will
    # set simulation.found to a list of the states that it could find that reach
    # the instruction we asked it to search for. Remember, in Python, if a list
    # is empty, it will be evaluated as false, otherwise true.
    if simulation.found:
        # Just take the first found solution
        solution_state = simulation.found[0]

        # Print the string that Angr wrote to stdin; this is our solution.
        print(solution_state.posix.dumps(sys.stdout.fileno()))
        solution0 = (solution_state.solver.eval(arg1, cast_to=bytes))
        solution1 = (solution_state.solver.eval(arg2, cast_to=bytes))

        print(solution0, solution1)

    else:
        # If Angr could not find a path that reaches print_good_address, throw an
        # error. Perhaps you mistyped the print_good_address?
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main()
