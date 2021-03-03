import sys
import getopt


class UI:
    """Base class for a handling a public key."""

    def __init__(self):
        """ Instiate the UI object."""
        argv = sys.argv[1:]
        self.inputfile = ''
        self.outputfile = ''
        try:
            opts, args = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
        except getopt.GetoptError:
            print('test.py -i <inputfile> -o <outputfile>')
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                # define the usage
                print('CreateCertificateBis.py -i <inputfile> [-o <outputfile>]')
                sys.exit()
            elif opt in ("-i", "--ifile"):
                self.inputfile = arg
            elif opt in ("-o", "--ofile"):
                self.outputfile = arg

    def getInputFile(self):
        """Get the inpufile."""
        return self.inputfile

    def isInputFile(self):
        """Return true if the input file exists."""
        return self.inputfile != ''
