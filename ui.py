import sys
import getopt

defaultConfiguration = {
    'options':'hi:o',
    'description':["ifile=", "ofile=","ccommand="],
    'usage':'CreateCertificateBis.py -c challenge|authentication [-i <inputfile>] [-o <outputfile>]'
}

class UI:
    """Base class for a handling a public key."""

    def __init__(self, configuration = defaultConfiguration):
        """ Instiate the UI object."""
        argv = sys.argv[1:]
        self.inputfile = ''
        self.outputfile = ''
        self.command = ''
        try:
            opts, args = getopt.getopt(argv, configuration['options'], configuration['description'])
        except getopt.GetoptError:
            print(configuration['usage'])
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                # define the usage
                print(configuration['usage'])
                sys.exit()
            elif opt in ("-i", "--ifile"):
                self.inputfile = arg
            elif opt in ("-o", "--ofile"):
                self.outputfile = arg
            elif opt in ("-c", "--ccommand"):
                self.command = arg
    
    def getInputFile(self):
        """Get the inpufile."""
        return self.inputfile

    def getOutputFile(self):
        """Get the inpufile."""
        return self.outputfile

    def getCommand(self):
        """Get the inpufile."""
        return self.command
    
    def isInputFile(self):
        """Return true if the input file exists."""
        return self.inputfile != ''

    def isCommand(self):
        """Return true if the input file exists."""
        return self.command != ''

    def isOutputFile(self):
        """Return true if the input file exists."""
        return self.outputfile != ''