const jsigs             = require('jsonld-signatures');
const {Ed25519KeyPair}  = require('crypto-ld');
const {documentLoaders} = require('jsonld');

const {Ed25519Signature2018}  = jsigs.suites;
const {AssertionProofPurpose} = jsigs.purposes;
const {node: documentLoader}  = documentLoaders;
const publicKeyBase58         = "GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza";
const privateKeyBase58        = "3cEzNVGdLoujfhWXqrbo1FgYy9GHA5GXYvB4KixHVuQoRbWbHTJP7XTkj6LqXeiFhw79v85E4wjPQc8WcdyzntcA";

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
    id:'did:example:fotiou',
    name: 'Nikos Fotiou',
    homepage: 'https://www.fotiou.gr',
    publicKey: [{
      type: 'Ed25519VerificationKey2018',
      id: 'did:example:fotiou#key1',
      controller: 'did:example:fotiou',
      publicKeyBase58: 'GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza'
    }],
    assertionMethod:[
      'did:example:fotiou#key1'
    ]
  };


async function sign(did_document)
{
  signature = await jsigs.sign(did_document, 
    {
      documentLoader,
      suite: new Ed25519Signature2018({
        verificationMethod: did_document.publicKey[0].id,
        key: new Ed25519KeyPair(
          {
            privateKeyBase58: privateKeyBase58,
            publicKeyBase58: did_document.publicKey[0].publicKeyBase58
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
        key: new Ed25519KeyPair(signedData.publicKey[0])
      }), 
      purpose: new AssertionProofPurpose({controller:doc})
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
