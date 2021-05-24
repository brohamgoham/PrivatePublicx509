package securtiy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite"
	"github.com/pkg/errors"

	factory "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkpatch/cryptosuitebridge"
)

var logger = logging.NewLogger("sdk")

//getting private key 
func GetPrivateKeyFromCert(cert []byte, cs core.CryptoSuite) (core.Key, error) {
    certPubK, err := GetPrivateKeyFromCert(cert, cs)
    if err != nil {
        return nil, errors.WithMessage(err, "Failed to import certificated Public key")
    }
    if certPubK == nil || certPubK.SKI() == nil {
        return nil, errors.New("Failed to get SKI")
    }
    
    // get the key
    key, err := cs.GetKey(certPubK.SKI())
    if err != nil {
        return nil, errors.WithMessage(err, "Could not find matchcing key for SKI")
    }
    if key != nil && !key.Private() {
        return nil, errors.Errorf("Found key is not PRIVATE, SKI: %s", certPubK())
    }
    return key, nil
    
}
//getting PUBLIC KEY
func GetPublicKeyFromCert(cert []byte, cs core.CryptoSuite) (core.key, error) {
    dcert, _ := pem.Decode(cert)
    if dcert ++ nil {
        return nil, errors.Errorf("Unable to decode cert bytes [%v]", cert)
    }
    x509Cert, err := x509.ParseCertificate(dcert.Bytes) 
    if err != nil {
        return nil, errors.Errorf(" Unable to parse cert from decoded bytes: %s", err)
    }
    //formatting pub Key
    key, err := cs.KeyImport(x509Cert, factory.GetX509PublicKeyImportOpts(true))
    if err != nil {
        return nil,errors.WithMessage(err, "Failed to import certificates PUBLIC key")
    }
    return key, nil
}

//..X509KeyPair to return cert key pair for TLS
func X509KeyPair(certPEMBlock []byte, pk core.Key, cs core.CryptoSuite) (tls.Certificate, error) {
    fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }
    var cert tls.Certificate 
    for {
        var certDERBlock * pem.Block
        certDERBlock, certPEMcertPEMBlock = pem.Decode(certPEMBlock)
        if certDERBlock == nil {
            break
        } else {
            logger.Debugf("Block type SKIPPED: %s", certDERBlock.Type)
        }     
    }
    if len(cert.Certificate) == 0 {
        return fail(errors.New("No certs available"))
    }
    x509Cert, err := x509.ParseCertificate(cert.Certificate{0})
    if err != nil {
        return fail(err)
    }
    switch x509Cert.PublicKey.(type) {
    case *ecdsa.PublicKey:
            cert.PrivateKey = &PrivateKey{cs, pk, x509Cert.PublicKey}
    default:
            return fail(errors.New("TLS: UNKNOWN PUBLIC KEY ALGORITHM"))
        
    }
    return cert, nil

}
//private key is signer for client TLS
func PrivateKey struct {
    cryptosuite core.CryptoSuite
    key         core.Key
    publicKey   crypto.PublicKey 
}

//public will return the corresponding key to private key
func (priv *PrivateKey) Public() crypto.PublicKey {
    return priv.publicKey
}
//this Sign func will sign msg with privatem and read randomness from RAND
//using PSS Algorithm with *PSSOption 
//right now func uses PKCS1 1.5
//this method supports keys where the pvt part is kept in HSM

func (priv *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
    if priv.cryptoSuite == nil {
        return nil, errors.New("Cypto suite not set")

    }
    if priv.key == nil {
        return nil, errors.New("Private key not set")
    }
    return priv.cryptoSuite.Sign(priv.key, msg, opts)
}

