package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"flag"

	//"log"

	"github.com/fatih/color"
	//"github.com/averagesecurityguy/spf"
	//dns "github.com/zmap/zdns"
)

func printBanner() {
	color.Magenta("" +
		"             \\|/\n" +
		"            .-*-\n" +
		"           / /|\\\n" +
		"          _L_\n" +
		"       ,\"   \".\n" +
		"   (\\ /  O O  \\ /)\n" +
		"    \\|    _    |/\n" +
		"      \\  (_)  /\n" +
		"      _/.___,\\_\n" +
		"     (_/     \\_)\n")
	color.Magenta("SMTP security checker (" + softwareVersion + ")\n")
	color.Magenta("####################################################\n\n")
}

// Check possible enumeration (VRFY, etc..)

func checkVRFY(server string, port int) bool {

	var msgNotOK = "VRFY available on port " + strconv.Itoa(port) + " !!! :-("
	var msgOK = "VRFY NOT FOUND on port " + strconv.Itoa(port) + " !!! :-)"
	var msgERRORconn = "Error during connection on port " + strconv.Itoa(port) + " !!! :-S"

	fmt.Print("Testing VRFY on PORT " + strconv.Itoa(port) + ": ")

	conn, err := net.DialTimeout("tcp", server+":"+strconv.Itoa(port), timeout)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			color.Cyan("PORT CLOSED?")
		} else {
			color.Yellow(msgERRORconn)
		}
		return false
	}

	c, err := smtp.NewClient(conn, server+":"+strconv.Itoa(port))
	if err != nil {
		//log.Fatal(err)
		color.Yellow(msgERRORconn)
		return false
	}

	vrfyExtension, _ := c.Extension("VRFY")

	if vrfyExtension {
		color.Red(msgNotOK)
	} else {
		color.Green(msgOK)
	}

	return vrfyExtension
}

func enumUsersVrfy(server string, port int, wordlist string) bool {

	conn, err := net.DialTimeout("tcp", server+":"+strconv.Itoa(port), timeout)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			color.Cyan("PORT CLOSED?")
		} else {
			color.Yellow("ff")
		}
		return false
	}

	c, err := smtp.NewClient(conn, server+":"+strconv.Itoa(port))
	if err != nil {
		log.Fatal(err)
		color.Yellow("ff")
		return false
	}

	defer c.Close()

	file, err := os.Open(wordlist)
	if err != nil {
		log.Fatal(err)
		return false
	}
	defer file.Close()

	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			//fmt.Println(scanner.Text()) // Println will add back the final '\n'
			userTest := scanner.Text()
			fmt.Print("Testing user: " + userTest + " -> ")
			res := c.Verify(userTest)
			if res != nil {
				color.Red(res.Error())
			} else {
				color.Green("OK! :)")
			}
		}
		if err := scanner.Err(); err != nil {
			return false
		}
	}

	return true
}

// Checks if (STARTTLS, TLS, SSL) are available

func checkSTARTTLS(server string, port int) bool { //Function OK!

	var msgOK = "STARTTLS OK on port " + strconv.Itoa(port) + " !!! :-)"
	var msgNotOK = "STARTTLS NOT FOUND on port " + strconv.Itoa(port) + " !!! :-("
	var msgERRORconn = "Error during connection on port " + strconv.Itoa(port) + " !!! :-S"

	fmt.Print("Testing STARTTLS on PORT " + strconv.Itoa(port) + ": ")

	conn, err := net.DialTimeout("tcp", server+":"+strconv.Itoa(port), timeout)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			color.Cyan("PORT CLOSED?")
		} else {
			color.Yellow(msgERRORconn)
		}
		return false
	}

	c, err := smtp.NewClient(conn, server+":"+strconv.Itoa(port))
	if err != nil {
		//log.Fatal(err)
		color.Yellow(msgERRORconn)
		return false
	}

	tlsState, _ := c.Extension("STARTTLS")

	if tlsState {
		color.Green(msgOK)
	} else {
		color.Red(msgNotOK)
	}
	return tlsState
}

func checkTLSSL(server string, port int) bool { //Function OK!

	var msgOK = "OK on port " + strconv.Itoa(port) + " !!! :-)"
	var msgNotOK = "NOT FOUND on port " + strconv.Itoa(port) + " !!! :-("
	var msgERRORconn = "Error during connection on port " + strconv.Itoa(port) + " !!! :-S"

	ok := false

	for version, goLib := range map[string]uint16{
		"SSLv3":   tls.VersionSSL30,
		"TLSv1.0": tls.VersionTLS10,
		"TLSv1.1": tls.VersionTLS11,
		"TLSv1.2": tls.VersionTLS12} {

		fmt.Print("Testing " + version + " on PORT " + strconv.Itoa(port) + ": ")

		dialerTimeout := &net.Dialer{
			Timeout: timeout,
		}

		tlsConfig := &tls.Config{
			MaxVersion: goLib,
			MinVersion: goLib,
		}

		conn, err := tls.DialWithDialer(dialerTimeout, "tcp", server+":"+strconv.Itoa(port), tlsConfig)
		if err != nil {
			if strings.Contains(err.Error(), "timeout") {
				color.Cyan("PORT CLOSED?")
			} else if strings.Contains(err.Error(), "EOF") {
				color.Cyan(version + " NOT AVAILABLE")
			} else if strings.Contains(err.Error(), "not look like a TLS handshake") {
				color.Red("NO TLS/SSL AVAILABLE")
			} else {
				color.Yellow(msgERRORconn + " | " + err.Error())
				//color.Yellow("error en Dial With Dialer")
			}
			continue
		}

		c, err := smtp.NewClient(conn, server+":"+strconv.Itoa(port))
		if err != nil {
			color.Red(msgNotOK)
			continue
		}
		c.Close()
		if version == "SSLv3" {
			color.Red("Santo cielo!!! Desactiva SSLv3 por favor...")
			ok = true
		} else {
			color.Green(msgOK)
			ok = true
		}

	}
	fmt.Println("--")
	return ok
}

// Check Relay
func checkRELAY(server string, port int, to string, from string, msg string) bool { //Function OK!

	fmt.Println("From: " + from)
	fmt.Println("To: " + to)

	// Connect to the remote SMTP server.
	c, err := smtp.Dial(server + ":" + strconv.Itoa(port))
	if err != nil {
		color.Yellow(err.Error())
		return false
	}

	// Set the sender and recipient first
	if err := c.Mail(from); err != nil {
		color.Yellow(err.Error())
		return false
	}
	if err := c.Rcpt(to); err != nil {
		color.Green(err.Error())
		return false
	}

	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		color.Yellow(err.Error())
		return true
	}
	_, err = fmt.Fprintf(wc, msg)
	if err != nil {
		color.Yellow(err.Error())
		return true
	}
	err = wc.Close()
	if err != nil {
		color.Yellow(err.Error())
		return true
	}

	// Send the QUIT command and close the connection.
	err = c.Quit()
	if err != nil {
		color.Yellow(err.Error())
		return true
	}

	color.Red("Relay ACCEPTED!!! gopher is sad :(")
	return true
}

// Check authentication (only for internal "from")
func checkUnauthSender(server string, port int, to string, from string, msg string) bool {
	fmt.Println("From: " + from)
	fmt.Println("To: " + to)

	// Connect to the remote SMTP server.
	c, err := smtp.Dial(server + ":" + strconv.Itoa(port))
	if err != nil {
		color.Yellow(err.Error())
		return false
	}

	// Set the sender and recipient first
	if err := c.Mail(from); err != nil {
		color.Yellow(err.Error())
		return false
	}
	if err := c.Rcpt(to); err != nil {
		color.Green(err.Error())
		return false
	}

	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		color.Yellow(err.Error())
		return true
	}
	_, err = fmt.Fprintf(wc, msg)
	if err != nil {
		color.Yellow(err.Error())
		return true
	}
	err = wc.Close()
	if err != nil {
		color.Yellow(err.Error())
		return true
	}

	// Send the QUIT command and close the connection.
	err = c.Quit()
	if err != nil {
		color.Yellow(err.Error())
		return true
	}

	color.Red("Unauthenticated send ACCEPTED!!! BAAAD!!!")
	return true
}

// Check banner versions
func checkBannerVulns() bool {
	return true
}

// More support functions
func isDomainName(possibleDomain string) bool { //Function OK!
	//Hay que arreglar la regexp (por ejemplo el dominio "alt4.gmail-smtp-in.l.google.com" no lo detecta)
	r, _ := regexp.Compile("^[a-zA-Z0-9][a-zA-Z0-9-.]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}$")
	return r.MatchString(possibleDomain)
}

func isIP(possibleIP string) bool { //Function OK!
	r, _ := regexp.Compile("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$")
	return r.MatchString(possibleIP)
}

func getReverseIP(ip string) string {
	reverseIP := ""
	splitIP := strings.Split(ip, ".")
	for _, byteIP := range splitIP {
		if reverseIP == "" {
			reverseIP = byteIP
		} else {
			reverseIP = byteIP + "." + reverseIP
		}
	}
	return reverseIP
}

func checkSpamHaus(server string) bool {
	spam := false
	rIP := getReverseIP(server)
	ips, err := net.LookupIP(rIP + ".sbl.spamhaus.org")
	if err != nil {
		//fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
		color.Green("SBL Not listed :) (" + server + ")")
	}
	if err == nil {
		for _, ip := range ips {
			fmt.Printf("SBL Listed: "+rIP+".sbl.spamhaus.org"+" IN A %s\n", ip.String())
		}
		spam = true
	}

	ips, err = net.LookupIP(rIP + ".xbl.spamhaus.org")
	if err != nil {
		//fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
		color.Green("XBL Not listed :) (" + server + ")")
	}
	if err == nil {
		for _, ip := range ips {
			fmt.Printf("XBL Listed: "+rIP+".sbl.spamhaus.org"+" IN A %s\n", ip.String())
		}
		spam = true
	}

	ips, err = net.LookupIP(rIP + ".pbl.spamhaus.org")
	if err != nil {
		//fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
		color.Green("PBL Not listed :) (" + server + ")")
	}
	if err == nil {
		for _, ip := range ips {
			color.Red("PBL Listed: "+rIP+".sbl.spamhaus.org"+" IN A %s\n", ip.String())
		}
		spam = true
	}
	return spam
}

// Funciones extras relacionadas con el correo
// 	Chequeo de listas negras
// 		- Dominios SPF en listas negras (blacklists)
//			- Recursividad de los includes (se comprueba todo)
//		- Comprobación seguridad de SPF (registros TXT)
//			- Recursividad de los includes (se comprueba todo)
//...

func checkSPFregisters(domainName string) bool {

	ips, err := net.LookupTXT("google.com")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get TXT records: %v\n", err)
		os.Exit(1)
	}
	for _, ip := range ips {
		fmt.Printf(ip + "\n")
	}

	return true
}

// Declaración de las principales variables usadas
var softwareVersion = "0.1 Beta"

var smtpPort = 25
var smtpPortSSL = 465
var smtpPortTLS = 587

var timeout = 4 * time.Second


//var BF_ENUM bool = false

// Variables para pruebas de desarrollo
//var smtpServer = "estafeta5.prosegur.com"
//var smtpServer = "84.78.25.181"
//var smtpServer = "165.227.133.37"

//var smtpServer = "eagle1.ingress.us"

//var smtpServer string = "localhost"
//------------------------------------------------------------------

// Flujo principal de la aplicación

var emailFromRelay string
var emailToRelay string
var internalEmail string
var wordlistUsersBt string
var vrfyBt bool
var smtpServer string




func init(){
//////////////////////////////////////////////////////////////////////////////////////////////////////////
/* PARAMETRIZACIÓN DEL PROGRAMA */
	const(
		defaultEmailFromRelay = "test@test.es"
		defaultEmailToRelay = "test@test.es"
		defaultInternalEmail = "test@test.es"
		defaultWordlistUsersBt = "/usr/share/wordlist/smtp_users.dic"
		defaultVrfyBt = false
		usage = "the variety of gopher"
	)

	flag.StringVar(&smtpServer, "server", "", usage)
	flag.StringVar(&emailFromRelay, "fromrelay", defaultEmailFromRelay, usage)
	flag.StringVar(&emailToRelay, "torelay", defaultEmailToRelay, usage)
	flag.StringVar(&internalEmail, "internalmail", defaultInternalEmail, usage)
	flag.StringVar(&wordlistUsersBt, "wordlist", defaultWordlistUsersBt, usage)
	flag.BoolVar(&vrfyBt, "bf", defaultVrfyBt, usage)

//////////////////////////////////////////////////////////////////////////////////////////////////////////
}





func main() {

	// CARGA DE PARÁMETROS
	flag.Parse()

	
	// MOSTRAR AYUDA SI NO EXISTEN LOS PARÁMETROS BÁSICOS NECESARIOS
	if smtpServer == "" {
		fmt.Println("Use: <command> [ OPTIONS ] --server <server>")
		fmt.Println("OPTIONS:")
		fmt.Println(" --fromrelay <from_email> # -> Custom FROM for test")
		fmt.Println(" --torelay <to_email> # -> Custom TO for test")
		fmt.Println(" --internalmail <internal_valid_email> # -> Valid internal organization mail")
		fmt.Println(" --bf  # -> Enable bruteforce user enumeration")
		fmt.Println(" --wordlist <wordlist_bruteforce> # -> Path of custom wordlist for bruteforce")
		fmt.Println("------------------------------------------------------\n")
		os.Exit(1)
	}


	// IMPRIMIR BANNER DE POSTUREO DE LA APLICACIÓN
	printBanner()


	// COMPROBAMOS QUE EL SERVIDOR A TESTEAR SEA VÁLIDO
	color.White("SCANNING SMTP " + smtpServer + "\n")
	if isDomainName(smtpServer) {
		color.Green("The server " + smtpServer + " is a valid domain name server!")
	} else if isIP(smtpServer) {
		color.Green("The server " + smtpServer + " is a valid IPv4 address!")
	} else {
		color.Red("The server " + smtpServer + " is NOT a valid SMTP server!!!!")
		os.Exit(1)
	}
	fmt.Print("\n")



	

	//phase 1 completed - Comprobación de capa de cifrado SSL v3, TLS v1.0 v1.1 v1.2
	color.Blue("CHECKING TLS/SSL:")
	checkTLSSL(smtpServer, smtpPortSSL)
	checkTLSSL(smtpServer, smtpPortTLS)
	checkTLSSL(smtpServer, smtpPort)
	fmt.Print("\n")
	// Checking function STARTTLS
	color.Blue("CHECKING STARTTLS:")
	checkSTARTTLS(smtpServer, smtpPort)
	checkSTARTTLS(smtpServer, smtpPortTLS)
	color.Blue("-----------------------------------")
	fmt.Print("\n")


	//////////////////////////////////////////////////////////////////////////////////////////////////////////
	//phase 2 completed - checking RELAY (función común de envío)
	color.Blue("CHECKING RELAY:")
	checkRELAY(smtpServer, smtpPort, emailToRelay, emailFromRelay, "Testing...")
	color.Blue("-----------------------------------")
	fmt.Print("\n")

	//phase 3 (check send valid to other unauthenticated) (función común de envío)
	color.Blue("CHECKING UNAUTH VALID USER (mail sending to external tests):")
	if internalEmail != "" {
		checkUnauthSender(smtpServer, smtpPort, emailToRelay, internalEmail, "Unauth OK!")
	}
	color.Blue("-----------------------------------")
	fmt.Print("\n")
	color.Blue("CHECKING UNAUTH VALID USER (mail sending to same tests):")
	if internalEmail != "" {
		checkUnauthSender(smtpServer, smtpPort, internalEmail, internalEmail, "Unauth to same OK!")
	}
	color.Blue("-----------------------------------")
	fmt.Print("\n")
	//////////////////////////////////////////////////////////////////////////////////////////////////////////


	//phase 4 completed
	color.Blue("CHECKING VRFY COMMAND:")
	resultVrfy := checkVRFY(smtpServer, smtpPort)
	if vrfyBt && resultVrfy {
		enumUsersVrfy(smtpServer, smtpPort, wordlistUsersBt)
	}
	color.Blue("-----------------------------------")
	fmt.Print("\n")

	//phase 5 completed
	color.Blue("CHECKING BLACK LIST SPAMHAUS (SBL, XBL, PBL):")
	if isIP(smtpServer) {
		color.White("IP: " + smtpServer)
		checkSpamHaus(smtpServer)
	} else {
		color.White("Domain: " + smtpServer)
		ips, err := net.LookupIP(smtpServer)
		if err != nil {
			//fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
			color.Red("No A registers for " + smtpServer)
		} else {
			for _, ip := range ips {
				checkSpamHaus(ip.String())
			}
		}
	}
	color.Blue("-----------------------------------")
	fmt.Print("\n")

}
