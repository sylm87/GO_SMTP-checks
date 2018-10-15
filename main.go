package main

import (
	"fmt"
	"strconv"
	"net"
	"net/smtp"
	"os"
	"time"
	//"log"
	"regexp"
	"github.com/fatih/color"
	//"github.com/averagesecurityguy/spf"
	//dns "github.com/zmap/zdns"
)

// Funciones de chequeo de enumeración

func check_VRFY() bool{
	return true
}

func enum_users() bool{
	return true
}

// Funciones de chequeo de cifrado disponibles

func check_STARTTLS(port int) bool{ //Función finalizada OK!

	var msgOK = "TLS OK on port " + strconv.Itoa(port) + " !!! :-)"
	var msgNotOK = "TLS NOT FOUND on port " + strconv.Itoa(port) + " !!! :-("
	var msgERRORconn = "Error during connection on port " + strconv.Itoa(port) + " !!! :-S"

	fmt.Print("Testing TLS on PORT " + strconv.Itoa(port) + ": ")

	conn, err := net.DialTimeout("tcp", SMTP_SERVER + ":" + strconv.Itoa(port), 4*time.Second)
	if err != nil {
		color.Yellow(msgERRORconn)
		return false
	}

	c, err := smtp.NewClient( conn, SMTP_SERVER + ":" + strconv.Itoa(port) )
	if err != nil {
		//log.Fatal(err)
		color.Yellow(msgERRORconn)
		return false
	}
	
	tlsState, _ := c.Extension("STARTTLS")

	if tlsState {
		color.Green(msgOK)
		return tlsState
	}else{
		color.Red(msgNotOK)
		return tlsState
	}
	
}


func check_SSL() bool{
	return true
}

// Funciones de chequeo de relay

func check_RELAY() bool{
	return true
}

// Funciones de chequeo de autenticación

func check_authentication() bool{
	return true
}

// Funciones de chequeo de versiones de servicios

func check_banner_vulns() bool{
	return true
}

// Funciones de apoyo

func isDomainName(possibleDomain string) bool{
	//Hay que arreglar la regexp (por ejemplo el dominio "alt4.gmail-smtp-in.l.google.com" no lo detecta)
	r, _ := regexp.Compile("^([a-zA-Z0-9]{1,1}[a-zA-Z0-9\\-_]{1,63}[a-zA-Z0-9]{1,1}[\\.]{1,1}){1,15}([a-zA-Z]{2,10})$")
	return r.MatchString(possibleDomain)
}

func isIP(possibleIP string) bool{
	r, _ := regexp.Compile("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$")
	return !r.MatchString(possibleIP)
}

// Funciones extras relacionadas con el correo
// 	Chequeo de listas negras
// 		- Dominios SPF en listas negras (blacklists)
//			- Recursividad de los includes (se comprueba todo)
//		- Comprobación seguridad de SPF (registros TXT)
//			- Recursividad de los includes (se comprueba todo)
//...

func checkSPFregisters(domainName string) bool{

	ips, err := net.LookupTXT("google.com")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get TXT records: %v\n", err)
		os.Exit(1)
	}
	for _, ip := range ips {
		fmt.Printf(ip+"\n")
	}

	return true
}


// Declaración de las principales variables usadas
var PORT_SMTP int = 25
//var PORT_SMTP_SSL int = 465
var PORT_SMTP_TLS int = 587

//var DICT_USERS string = "/usr/share/wordlist/smtp_users.dic"
//var EMAIL_FROM_RELAY string = "fromrelay@peta.prsgr.us"
//var EMAIL_TO_RELAY string = "torelay@peta.prsgr.us"

//var BF_ENUM bool = false


// Variables para pruebas de desarrollo

var SMTP_SERVER string = "alt4.gmail-smtp-in.l.google.com"
//var SMTP_SERVER string = "localhost"
//------------------------------------------------------------------

// Flujo principal de la aplicación

func main() {

	//fmt.Println(isDomainName(SMTP_SERVER))
	fmt.Println("CHECKING TLS:")
	check_STARTTLS(PORT_SMTP)
	check_STARTTLS(PORT_SMTP_TLS)
	fmt.Println("\n-----------------------------------\n")

	fmt.Println("Fin de ejecución!!!")

}
