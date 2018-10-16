package main

import (
	"fmt"
	"strconv"
	"net"
	"crypto/tls"
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

func check_STARTTLS(server string, port int) bool{ //Función finalizada OK!

	var msgOK = "STARTTLS OK on port " + strconv.Itoa(port) + " !!! :-)"
	var msgNotOK = "STARTTLS NOT FOUND on port " + strconv.Itoa(port) + " !!! :-("
	var msgERRORconn = "Error during connection on port " + strconv.Itoa(port) + " !!! :-S"

	fmt.Print("Testing STARTTLS on PORT " + strconv.Itoa(port) + ": ")

	conn, err := net.DialTimeout("tcp", server + ":" + strconv.Itoa(port), 10*time.Second)
	if err != nil {
		color.Yellow(msgERRORconn)
		return false
	}

	c, err := smtp.NewClient( conn, server + ":" + strconv.Itoa(port) )
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

func check_TLS(server string, port int) bool{ //Función finalizada OK!

	var msgOK = "OK on port " + strconv.Itoa(port) + " !!! :-)"
	var msgNotOK = "NOT FOUND on port " + strconv.Itoa(port) + " !!! :-("
	var msgERRORconn = "Error during connection on port " + strconv.Itoa(port) + " !!! :-S"

	/* 

	En esta zona (al abrir el Dial TLS/SSL) hay que forzar las versiones máximas de SSL admitidas para poder comprobar los servicios con:
	- SSLv3
	- TLSv1.0
	- TLSv1.1
	- TLSv1.2

	*/

	ok := false

	for version, go_lib := range (map[string]uint16{
		"SSLv3": tls.VersionSSL30 , 
		"TLSv1.0": tls.VersionTLS10, 
		"TLSv1.1" : tls.VersionTLS11, 
		"TLSv1.2" : tls.VersionTLS12 }) {
		
		fmt.Print("Testing " + version + " on PORT "+strconv.Itoa(port)+": ")

		dialer_timeout := &net.Dialer{
			Timeout: 10*time.Second,
		}

		tls_config := &tls.Config{
			MaxVersion: go_lib,
			MinVersion: go_lib,
		}


		conn, err := tls.DialWithDialer(dialer_timeout , "tcp", server+":"+ strconv.Itoa(port), tls_config)
		if err != nil {
			color.Yellow(msgERRORconn + " | "+ err.Error())
			//color.Yellow("error en Dial With Dialer")
			continue
		}

		c,err := smtp.NewClient(conn, server+":" +strconv.Itoa(port))
		if err != nil {
			color.Red(msgNotOK)
			continue
		}
		c.Close()
		if version == "SSLv3" {
			color.Red("Santo cielo!!! Desactiva SSLv3 por favor...")
		} else {
			color.Green(msgOK)
			ok = true
		}

	}

	return ok
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
var PORT_SMTP_SSL int = 465
var PORT_SMTP_TLS int = 587

//var DICT_USERS string = "/usr/share/wordlist/smtp_users.dic"
//var EMAIL_FROM_RELAY string = "fromrelay@peta.prsgr.us"
//var EMAIL_TO_RELAY string = "torelay@peta.prsgr.us"

//var BF_ENUM bool = false


// Variables para pruebas de desarrollo

var SMTP_SERVER string = "estafeta5.prosegur.com"
//var SMTP_SERVER string = "localhost"
//------------------------------------------------------------------

// Flujo principal de la aplicación

func main() {

	//fmt.Println(isDomainName(SMTP_SERVER))
	fmt.Println("CHECKING TLS:")
	check_TLS(SMTP_SERVER, PORT_SMTP_SSL)
	check_TLS(SMTP_SERVER, PORT_SMTP_TLS)
	check_TLS(SMTP_SERVER, PORT_SMTP)
	fmt.Print("\n\n")
	fmt.Println("CHECKING STARTTLS:")
	check_STARTTLS(SMTP_SERVER, PORT_SMTP)
	check_STARTTLS(SMTP_SERVER, PORT_SMTP_TLS)
	
	fmt.Println("\n-----------------------------------\n")

	fmt.Println("Fin de ejecución!!!")

}
