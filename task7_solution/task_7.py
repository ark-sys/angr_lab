import angr
import claripy

def main(bin = './task_7'):
    # Create an Angr project.
    project = angr.Project(bin)

    # start at the beginning of task6

    entry_point=0x4013F2
    initial_state = project.factory.blank_state(addr=entry_point)

    # hook the function read_six_numbers which has a reference to the address of where the integers are stored (during input phase)
    class read_six_numbers(angr.SimProcedure):
        bvs_list = []
        input_ints = []

        # read_six_numbers takes two parameters
        # the first one is the input string provided from stdin
        # the second is the location of the array in which the integers will be formatted (thanks to scanf)
        def run(self, mock_input_string, array_addr):
            self.input_ints.append(array_addr)
            # create a bvs for each integer and store it at the place where input integers should be stored
            for i in range(6):
                bvs = self.state.solver.BVS("int_{}".format(i), 32)
                self.bvs_list.append(bvs)
                self.state.mem[array_addr].int.array(6)[i] = bvs

            return 6

    # hook at the address where the function read_six_numbers is located
    read_six_numbers_addr=0x401372
    project.hook(read_six_numbers_addr,read_six_numbers())


    # Create a simulation manager initialized with the starting state. It provides
    # a number of useful tools to search and execute the binary.

    # here we use the veritesting option that allows us to avoid path explosion since there are multiple loops in the binary

    simulation = project.factory.simgr(initial_state, veritesting=True)

    # Avoid all states that can potentially print an error message
    avoid_addr=[0x401462,0x4014BB, 0x401608,0x40164E]
    # Make sure to pass from these addresses which are located just after the error message
    find_addr=[0x401671]

    simulation.explore(find=find_addr, avoid=avoid_addr)

    # Check that we have found a solution. The simulation.explore() method will
    # set simulation.found to a list of the states that it could find that reach
    # the instruction we asked it to search for. Remember, in Python, if a list
    # is empty, it will be evaluated as false, otherwise true.
    if simulation.found:

        # Just take the first found solution
        solution_state = simulation.found[0]

        # then evaluate each integer from the bvs list
        print(' '.join([str(solution_state.solver.eval(x)) for x in read_six_numbers.bvs_list]))

    else:
        # If Angr could not find a path that reaches print_good_address, throw an
        # error. Perhaps you mistyped the print_good_address?
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main()
