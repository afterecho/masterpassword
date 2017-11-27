// Copyright 2017 Darren Gibb
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command gompw is a Go implementation of the masterpassword tool.  For more details
// see http://masterpasswordapp.com/
package main

import (
	"fmt"
	"flag"
	"bufio"
	"os"
	"golang.org/x/crypto/ssh/terminal"
	"github.com/afterecho/masterpassword/masterpassword"
	"strconv"
	"sort"
)

const VERSION = "1.0.0"
const EXIT_OK = 0
const EXIT_ERROR = 1
const EXIT_MISSING_PASSWORD = 3
const EXIT_BAD_PASSWORD_TYPE = 4

func doMasterPassword() int {
	validPwtypes := masterpassword.GetPasswordTypeMap()

	flag.Usage = func() {
		showHelp(validPwtypes)
	}

	var help bool
	flag.BoolVar(&help, "h", false, "")
	flag.BoolVar(&help, "help", false, "")

	var version bool
	flag.BoolVar(&version, "v", false, "")
	flag.BoolVar(&version, "version", false, "")

	var username string
	flag.StringVar(&username, "u", os.Getenv("MPW_FULLNAME"), "")

	sitecounterEnv := os.Getenv("MPW_SITECOUNTER")
	sitecounterEnvNum, err := strconv.ParseInt(sitecounterEnv, 0, 0)

	if err != nil {
		sitecounterEnvNum = 1
	} else {
		sitecounterEnvNum = sitecounterEnvNum
	}

	var sitecounter int
	flag.IntVar(&sitecounter, "c", int(sitecounterEnvNum), "")

	pwtypeEnv := os.Getenv("MPW_PWTYPE")
	if pwtypeEnv == "" {
		pwtypeEnv = "l"
	}

	var pwtype string
	flag.StringVar(&pwtype, "t", pwtypeEnv, "")

	var mpwFd int
	flag.IntVar(&mpwFd, "m", -1, "")

	flag.Parse()

	sitename := os.Getenv("MPW_SITE")
	if sitename == "" {
		sitename = flag.Arg(0)
	}

	if help {
		showHelp(validPwtypes)
		return EXIT_OK
	}

	if version {
		showVersion()
		return EXIT_OK
	}

	if _, ok := validPwtypes[pwtype]; !ok {
		fmt.Fprintf(os.Stderr, "Unknown password type: %s\n", pwtype)
		return EXIT_BAD_PASSWORD_TYPE
	}

	if username == "" {
		username = promptForInput("Username")
	}

	if sitename == "" {
		sitename = promptForInput("Site")
	}

	var masterPasswordBytes []byte

	if mpwFd != -1 {
		mpwFile := bufio.NewScanner(os.NewFile(uintptr(mpwFd), ""))
		mpwFile.Scan()
		masterPasswordBytes = mpwFile.Bytes()
	} else {
		masterPasswordEnv := os.Getenv("MPW_MASTERPASSWORD")
		if masterPasswordEnv == "" {
			fmt.Fprint(os.Stderr, "Master password: ")
			masterPasswordBytes, _ = terminal.ReadPassword(0)
			fmt.Fprint(os.Stderr, "\n")
		} else {
			masterPasswordBytes = []byte(masterPasswordEnv)
		}
	}
	if len(masterPasswordBytes) == 0 {
		fmt.Fprintln(os.Stderr, "Missing master password")
		return EXIT_MISSING_PASSWORD
	}

	password, err := masterpassword.Password(username, sitename, sitecounter, pwtype, masterPasswordBytes)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failure: %s\n", err)
		return EXIT_ERROR
	}

	fmt.Print(password)
	if terminal.IsTerminal(1) {
		fmt.Println()
	}
	return EXIT_OK
}

func showHelp(validPwtypes map[string]masterpassword.Template) {
	fmt.Fprintf(os.Stderr,"Usage: %s [-u full-name] [-t pw-type] [-c counter] [-m fd]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "      [-h] sitename")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  -u full-name Specify the full name of the user.")
	fmt.Fprintln(os.Stderr, "               Defaults to MPW_FULLNAME in env or prompts.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  -c counter   The value of the counter.")
	fmt.Fprintln(os.Stderr, "               Defaults to MPW_SITECOUNTER in env or 1.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  -t pw-type   Specify the password's template.")
	fmt.Fprintln(os.Stderr, "               Defaults to MPW_PWTYPE in env or 'long'")
	var pwtypes []string
	for pwtype := range validPwtypes {
		pwtypes = append(pwtypes, pwtype)
	}
	sort.Strings(pwtypes)
	for _, pwtype := range pwtypes {
		fmt.Printf("                   %s | %s\n", pwtype, validPwtypes[pwtype].Description)
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  -m fd        Read the master password of the user from a file descriptor.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  sitename     The website name the password is for.")
	fmt.Fprintln(os.Stderr, "               Defaults to MPW_SITE in env or prompts.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  If variable MPW_MASTERPASSWORD is set use it for the")
	fmt.Fprintln(os.Stderr, "  master password instead of prompting. This should not")
	fmt.Fprintln(os.Stderr, "  be used as it may expose your password to other users")
	fmt.Fprintln(os.Stderr, "  on the system.")
}

func showVersion() {
	fmt.Fprintf(os.Stderr,"%s %s, library version %s\n", os.Args[0], VERSION, masterpassword.VERSION)
}

func promptForInput(prompt string) string {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text()
}

func main() {
	os.Exit(doMasterPassword())
}
