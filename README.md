# wpbrute
Python tool that can be used to perform an augmented bruteorce attack on a wordpress site. This tool is meant to be used for educational purposes only.
## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install required modules

```bash
pip install -r requirements.txt
```

## Demo
Demo: https://www.youtube.com/watch?v=r1i7M_83oL4

## Usage

Get all the available options by:
```bash
python2.7 wpbrute.py -h
```

```bash
__          _______  ____  _____  _    _ _______ ______ 
\ \        / /  __ \|  _ \|  __ \| |  | |__   __|  ____|
 \ \  /\  / /| |__) | |_) | |__) | |  | |  | |  | |__   
  \ \/  \/ / |  ___/|  _ <|  _  /| |  | |  | |  |  __|  
   \  /\  /  | |    | |_) | | \ \| |__| |  | |  | |____ 
    \/  \/   |_|    |____/|_|  \_\\____/   |_|  |______|
Version: 1.0. Works for Wordpress versions <4.4
+-+-+-+-+-+-+-+-+-+ +-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+
|d|e|v|e|l|o|p|e|d| |b|y|:| |A|n|g|e|l|o| |A|l|t|a|m|i|r|a|n|o|
+-+-+-+-+-+-+-+-+-+ +-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+ 
Usage: ./wpbrute [Mode of operation] [options]
MODES OF OPERATION:
  -S    Scan mode:  Scans subnet or ip for a wordpress installation
                    required: -t/--target
                    optional: --root-directory (e.g."/example/")
  -R    Recon mode: Checks if users can be enumerated, usernames bruteforced and xmlrpc requests sent
                    required: -t/--target
  -E    Enum mode:  Enumerates usernames.
                    required: -t/--target, -E [needs an argument]
  -B    Brute mode: Bruteforcing mode that performs the xmlrpc augmented bruteforcing attack (default mode)
                    required: -t/--target, -u/-U, -P
                    optional: --sleep-time
  -A    Auto mode:  Checks if the site is running wordpress, checks if XML-RPC is enabled, enumerates usernames
                    and starts augmented bruteforcing process. A fully automated bruteforcing mode.
                    required: -t/--target
OPTIONS:
  -t    target:     accepts the address of the target at the wordpress root path
                    ("--target=" can also be used)
  -u    username:   Accepts as an argument a username
  -U    usernames:  Accepts as an argument the path of the username list (not implemented yet)
  -P    passwords:  Accepts as an argument the path of the wordlist
  -h    help:       Prints the help information
  --sleep-time=     Sets the time in seconds in-between requests
  --root-directory= Sets the root directory of the wordpress installation (default is "/")
  --request-size=   Sets the size of the XML-RPC requests (<950 recommended)
EXAMPLES:
  ./wpbrute.py -A -t http://127.0.0.1/wordpress4.3.19/
  ./wpbrute.py -R -t http://127.0.0.1/wordpress4.3.19/
  ./wpbrute.py -S -t 192.168.1.0/24 --root-directory=/wordpress4.3.19/
  ./wpbrute.py -E 5 -t http://127.0.0.1/wordpress4.3.19/
  ./wpbrute.py -B -t http://127.0.0.1/wordpress4.3.19/ -u me -P dictionaries/rockyou.txt --sleep-time=1
```
## Tested On
- Linux Mint

