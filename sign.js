const jsigs             = require('jsonld-signatures');
const {Ed25519KeyPair}  = require('crypto-ld');
const {documentLoaders} = require('jsonld');

const {Ed25519Signature2018}  = jsigs.suites;
const {AssertionProofPurpose} = jsigs.purposes;
const {node: documentLoader}  = documentLoaders;
const publicKeyBase58         = "GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza";
const privateKeyBase58        = "3cEzNVGdLoujfhWXqrbo1FgYy9GHA5GXYvB4KixHVuQoRbWbHTJP7XTkj6LqXeiFhw79v85E4wjPQc8WcdyzntcA";

// specify the public key object
const publicKey = {
  '@context': jsigs.SECURITY_CONTEXT_URL,
  type: 'Ed25519VerificationKey2018',
  id: 'https://github.com/nikosft#key1',
  controller: 'https://github.com/nikosft',
  publicKeyBase58
};

// specify the public key controller object
const controller = {
  '@context': jsigs.SECURITY_CONTEXT_URL,
  id: 'https://github.com/nikosft',
  publicKey: [publicKey],
  assertionMethod: [publicKey.id]
};

// create the JSON-LD document that should be signed
const doc = {
    '@context': [
     "https://w3id.org/security/v2",
      {
        schema: 'http://schema.org/',
        name: 'schema:name',
        homepage: 'schema:url',
      }
    ],
    name: 'Nikos Fotiou',
    homepage: 'https://www.fotiou.gr',
  };


async function sign(jsonData)
{
  signature = await jsigs.sign(jsonData, 
    {
      documentLoader,
      suite: new Ed25519Signature2018({
        verificationMethod: publicKey.id,
        key: new Ed25519KeyPair(
          {
            privateKeyBase58: privateKeyBase58,
            publicKeyBase58: publicKeyBase58
          })
      }), 
    purpose: new AssertionProofPurpose()
  })
  return signature
}

async function verify(signedData)
{
  result = await jsigs.verify(signedData, 
    {
      documentLoader,
      suite: new Ed25519Signature2018({
        key: new Ed25519KeyPair(publicKey)
      }), 
      purpose: new AssertionProofPurpose({controller})
  })
  return result
}

sign(doc).then(signedData => {
  console.log(signedData);
  verify(signedData).then(result=>
    {
      if(result.verified) {
        console.log('Signature verified.');
      } else {
        console.log('Signature verification error:', result.error);
      }
  })
})
