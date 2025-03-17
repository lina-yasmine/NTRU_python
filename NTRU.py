import argparse
import sys
from os.path import exists
from NTRU.NTRUencrypt import NTRUencrypt
from NTRU.NTRUdecrypt import NTRUdecrypt

def generate_keys(args):
    """Generate public and private keys based on arguments."""
    N1 = NTRUdecrypt()
    if args.moderate_sec:
        N1.setNpq(N=107, p=3, q=64, df=15, dg=12, d=5)
    elif args.highest_sec:
        N1.setNpq(N=503, p=3, q=256, df=216, dg=72, d=55)
    else:
        N1.setNpq(N=167, p=3, q=128, df=61, dg=20, d=18)

    #Generating Alice's private and public keys
    N1.genPubPriv(args.key_name)
    N1.readPub(args.key_name + ".pub")
    N1.readPriv(args.key_name + ".priv")

    print("\nAlice's Public Key:")
    print("p = ", N1.p)
    print("q = ", N1.q)
    print("N = ", N1.N)
    print("d = ", N1.dr)
    print("h = ", N1.h)

    print("\nAlice's Private Key:")
    print("p = ", N1.p)
    print("q = ", N1.q)
    print("N = ", N1.N)
    print("df = ", N1.df)
    print("dg = ", N1.dg)
    print("d = ", N1.dr)
    print("f = ", N1.f)
    print("fp = ", N1.fp)
    print("fq = ", N1.fq)
    print("g = ", N1.g)


def encrypt_data(args):
    """Encrypt data using the given public key."""
    if not exists(args.key_name + ".pub"):
        sys.exit("ERROR : Public key '" + args.key_name + ".pub' not found.")

    if args.Enc_string and args.Enc_file:
        sys.exit("ERROR : More than one input to encrypt given.")

    if not args.out_file and not args.out_in_term:
        sys.exit("ERROR : At least one output method must be specified.")

    E = NTRUencrypt()
    E.readPub(args.key_name + ".pub")

        # Extract the data to encrypt
    if args.Enc_string:
            to_encrypt = args.Enc_string
    elif args.Enc_file:
            # Need to check if the file exists
        if not exists(args.Enc_file):
                sys.exit("ERROR : Input file '"+args.Enc_file+"' not found.")
            # If it does then read all the data from it
        with open(args.Enc_file,"r") as f:
                to_encrypt = "".join(f.readlines())

    print("Original message:", to_encrypt)

    E.encryptString(to_encrypt)

    print("Encrypted message:", E.Me)

    if args.out_in_term:
        print(E.Me)
    elif args.out_file:
        with open(args.out_file, "w") as f:
            f.write(E.Me)

def decrypt_data(args):
 # Decrypt some data using the known private key

        # First check if the private key file exists
        if not exists(args.key_name+".priv"):
            sys.exit("ERROR : Public key '"+args.key_name+".priv' not found.")

        # We can only have one input to decrypt
        if args.Dec_string and args.Dec_file:
            sys.exit("ERROR : More than one input to decrypt given.")
                    
        # We need an output method specified
        if not args.out_file and not args.out_in_term:
            sys.exit("ERROR : At least one output method must be specified.")

        # Then initialise an decryption class
        D = NTRUdecrypt()

        # And read the public key
        D.readPriv(args.key_name+".priv")

        # Extract the data to decrypt
        if args.Dec_string:
            to_decrypt = args.Dec_string
        elif args.Dec_file:
            # Need to check if the file exists
            if not exists(args.Dec_file):
                sys.exit("ERROR : Input file '"+args.Dec_file+"' not found.")
            # If it does then read all the data from it
            with open(args.Dec_file,"r") as f:
                to_decrypt = "".join(f.readlines())

        # Then decrypt the string
        D.decryptString(to_decrypt)
        
        # And output the decrypted data
        if args.out_in_term:
            # Just print the encrypted data to the terminal
            print(D.M)
        elif args.out_file:
            # Write the encrypted data to an output file
            with open(args.out_file,"w") as f:
                f.write(D.M)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="NTRU Encrypt/Decrypt", description="An implementation of the NTRU encryption algorithm in python3.", epilog="References:\n[1] Hoffstein J, Pipher J, Silverman JH. NTRU: A Ring-Based Public Key Cryptosystem. In: International Algorithmic Number Theory Symposium. Springer; 1998. p. 267--288.", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-k", "--key-name", default="key", type=str, help="The filename of the public and private keys (key_name.pub and (key_name.priv).")
    parser.add_argument("-G", "--Gen", action="store_true", help="Generate the public and private key files.\nDefault key parameters are the high security parameters from [1].")
    parser.add_argument("-M", "--moderate_sec", action="store_true", help="Generate moderate security keys from [1] with N=107, p=3, q=64.")
    parser.add_argument("-H", "--high-sec", action="store_true", help="Generate high security keys from [1] with N=167, p=3, q=128.")
    parser.add_argument("-HH", "--highest-sec", action="store_true", help="Generate highest security keys from [1] with N=503, p=3, q=256.")
    parser.add_argument("-N", "--N", default=167, type=int, help="The order of the polynomial ring, default 503.")
    parser.add_argument("-p", "--p", default=3, type=int, help="The smallest inverse polynomial modulus, default 3.")
    parser.add_argument("-q", "--q", default=128, type=int, help="The largest inverse polynomial modulus, default 256.")
    parser.add_argument("-df", "--df", default=61, type=int, help="Polynomial f has df 1's and df -1's, default 61.")
    parser.add_argument("-dg", "--dg", default=20, type=int, help="Polynomial g has dg 1's and -1's, default 20.")
    parser.add_argument("-d", "--d", default=18, type=int, help="Random obfuscating polynomial has d 1's and -1's, default 18.")
    parser.add_argument("-O", "--out_file", type=str, help="Output file for encrypted/decrypted data/string.")
    parser.add_argument("-T", "--out_in_term", action="store_true", help="Output encrypted/decrypted data/string to terminal.")
    parser.add_argument("-eS", "--Enc_string", type=str, help="Encrypt the string given as an input.\nNote: String must be given in quotation marks, e.g. \"a string\".\nNote: This always requires a known public key.")
    parser.add_argument("-eF", "--Enc_file", type=str, help="Encrypt the string given in this input file.\nNote: This always requires a known public key.")
    parser.add_argument("-dS", "--Dec_string", type=str, help="Decrypt the string given as an input.\nNote: String must be given in quotation marks, e.g. \"a string\".\nNote: This always requires a known private key.")
    parser.add_argument("-dF", "--Dec_file", type=str, help="Decrypt the string given in this input file.\nNote: This always requires a known private key.")
    args = parser.parse_args()

    if args.Gen:
        generate_keys(args)
    elif args.Enc_string or args.Enc_file:
        encrypt_data(args)
    elif args.Dec_string or args.Dec_file:
        decrypt_data(args)
