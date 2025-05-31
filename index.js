/*
    NOTICE:

    This is a simple express server that uses the cloudAgentWallet class to interact with aca-py.

    Normally you would need use a JWT token to authenticate yourself while using this server, for example an authorised superuser could generate schemas, issue credentials.
    And a regular user would be able to receive credentials based on what they have on the server,
    for example if the user was interacting with the government and wanted to get their ID,
    They would login to the government's server and that server would send a request to this server for issuence based on the users name, surname etc...

    What I had in mind was this: Admin role can create new schemas, new credDef's etc, and regular users can run issueCredential using the admins wallet.
    But the admin wallet keys had to be secured, so I created this server instead of hardcoding the passphrase into the node module indy-bex-connector.

    BUT:

    For this demo, we wont have any authentication/authorization, because it is complicated and there is a time window of only 1 month.
    Also the mnemonic is hardcoded as well as the aca-py url.
    Normally you would send those when starting the app, but this is just for a demo on the usage of credilink connect browser extension.
*/

import * as bip39 from '@scure/bip39';
import { wordlist as englishWordlist } from '@scure/bip39/wordlists/english';
import CryptoJS from 'crypto-js';
import bs58 from 'bs58';
import { Buffer } from 'buffer';
import cors from 'cors';
import express from 'express';
var database = {hiring: []}; //sorry
const app = express();
app.use(express.json());
app.use(cors({
  origin: 'http://localhost:9000'
}));

const PORT = 3000;
var wallet = null;
app.listen(PORT, () => {
    console.log("Server Listening on PORT:", PORT);
    wallet = new cloudAgentWallet("http://localhost:8003");
  });
  //acapy
  app.get('/init',async (request, response)=> {
    await wallet.initialiseWalletInstance("crime sure about liquid pelican goat cancel balance axis lock sting toilet");

    response.send({data: "initialised"});
  })

  app.get('/generateNewDid',async (request, response)=> {
    await wallet.generateNewDID();
    response.send({data: "generated new DID"});
  })
  app.get('/listDids', async (request, response) => {
    var dids = await wallet.listDIDs();
    console.log(dids);
    response.send(dids);
  })
  app.get('/getCredentialDefinitions',async (request,response) => {
    var credDefs = await wallet.getCredentialDefinitions(request.query.schemaId);
    console.log(credDefs);
    if(credDefs == null) {
      response.send({data: {credential_definition_ids : []}});
      return;
    }
    response.send({data: {credential_definition_ids : [credDefs]}});
  })
  app.post('/createCredentialDefinition', async (request, response) => {
    var res = await wallet.createCredentialDefinition(request.body);
    response.send({data: res});
  });
  app.post('/createSchema', async (request, response) => {
    var res = await wallet.createSchema(request.body);
    console.log(res);
    response.send({schema_ids: [res]});
    });
  app.get('/schemas', async (request, response)=> {
    var schemas = await wallet.getSchemas();
    response.send(schemas);
  })
  app.get('/getSchemaProperties', async (request, response) => {
    var schemaProps = await wallet.getSchemaProperties(request.query.schemaId);
    response.send(schemaProps);
  });
  app.post('/connect', async (request, response) => {
    var res = await wallet.connect(request.body.goal,request.body.goal_code,request.body.alias,request.body.label,request.body.multiUse,request.body.requesterUrl);
    response.send(res);
  });
  app.post('/issueCredential', async (request, response) => {
    var res = await wallet.issueCredential(request.body);
    response.send(res);
  });
  app.post('/createProofRequest', async (request, response) => {
    var res = await wallet.createProofRequest(request.body);
    response.send(res);
  });
  app.post('/verifyProof', async (request, response) => {
    var res = await wallet.verifyProof();
    response.send(res);
  });


  //other credilink functions
  app.post('/newHiringDoc', async (request, response) => {
    database.hiring.push(request.body);
    response.send({status: "200"});
  });
  app.get('/getHiringDocs', async (request, response) => {
    response.send(database.hiring);
  });
  app.post('/applyToJob', async (request, response) => {
    var body = request.body;
    var id = body.id;
    var doc = database.hiring.find(x => x.jobId == body.jobId);
    if(doc.nominees == null) {
      doc.nominees = {};
    }
    doc.nominees[id] = {status: "pending"};
    response.send({status: "200"});
  });
  app.post('/newConnection', async (request, response) => {
    //find invitedUser on database.hiring
    var doc = database.hiring.find(x => x.jobId == request.body.jobId);
    doc.nominees[request.body.invitedUser] = {
      invitation : request.body.invitation,
      inviMsgIdRequester : request.body.inviMsgId,
      status: request.body.status
    }
    response.send({status: "200"});
  })
  app.put('/acceptConnection', async (request, response) => {
    var doc = database.hiring.find(x => x.jobId == request.body.jobId);
    doc.nominees[request.body.userId].inviMsgIdRequestee = request.body.invi_msg_id;
    doc.nominees[request.body.userId].status = "done";
    response.send({status: "200"});
  });
  app.put('/proofRequestSent', async (request, response) => {
    var doc = database.hiring.find(x => x.jobId == request.body.jobId);
    doc.nominees[request.body.userId].status = "proof-request-sent";
    response.send({status: "200"});
  });
  app.put('/presentationSent', async (request, response) => {
    var doc = database.hiring.find(x => x.jobId == request.body.jobId);
    doc.nominees[request.body.userId].status = "presentation-sent";
    response.send({status: "200"});
  });
  app.get("/status", (request, response) => {
    const status = {
       "Status": "Running"
    };
    
    response.send(status);
 });


 // src/index.js
 class cloudAgentWallet {
  #walletName;
  #walletKey;
  #walletToken;
  #walletId;
  acapy_url;
  #invi_msg_id;
  constructor (acapy_url) {
    this.acapy_url = acapy_url;
  }
  /*
    Initialises instance of the wallet.
    Connects to C# API and that API connects to aca_py
    wallet actions:
    - generate new wallet based on mnemonic or without mnemonic 
    - get existing wallet
    - generate a new DID
    - list existing DID's
    - create schema (MUST BE ENDORSER, STEWARD OR TRUSTEE, or change the default auth_map_rules on the nodes.)
    - get schemas created by this wallet.
    - create credDef and schema at the same time using the same DID
    - create credDef
    - issue credential

  */

    //public methods
    //initialises new wallet instance, if a mnemonic is provided, generates the wallet according to that wallet, or opens the wallet if it exists on aca-py side.
  async initialiseWalletInstance(mnemonic) {
    //javascript does not have overloading ?
    if(mnemonic == null) {
      return this.#initialiseWalletInstanceWithoutMnemonic();
    } else {
      return this.#initialiseWalletInstanceWithMnemonic(mnemonic);
    }   
  }
  //the generated DID must be published to the ledger if it is going to be used as a steward,
  async generateNewDID() {
    if(this.#walletToken == null || this.#walletId == null) {
      throw new Error('Wallet not initialised, initialiseWalletInstance(withOrWithoutMnemonic) must be called first');
    }
    try {
      // Wait for the token to be retrieved from storage
      const token = this.#walletToken;
  
      // Define the request options
      var requestOptions = {
        method: "POST",
        headers: {
          "accept": "application/json",
          "Content-Type": "application/json", // Make sure to send JSON data
          "Authorization": `Bearer ${token}` // Add the JWT token to the headers
        },
        redirect: "follow",
      };
  
      // Await the fetch call and parse the response as JSON
      const response = await fetch(this.acapy_url+ "/wallet/did/create", requestOptions);
  
      // Check if the response is OK (status code 200-299)
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
  
      // Parse the response as JSON
      const result = await response.json();
      
  
      return result; // Return the parsed JSON result
    } catch (error) {
      console.error("Error during DID creation:", error);
      throw error; // Re-throw the error so it can be caught elsewhere if needed
    }
  }
  async listDIDs() {
    
    console.log("walletToken", this.#walletToken);
    try {
      // Wait for the token to be retrieved from storage
      const token = this.#walletToken;
  
      // Define the request options
      var requestOptions = {
        method: "GET",
        headers: {
          "accept": "application/json",
          "Content-Type": "application/json", // Make sure to send JSON data
          "Authorization": `Bearer ${token}` // Add the JWT token to the headers
        },
        redirect: "follow",
      };
  
      // Await the fetch call and parse the response as JSON
      const response = await fetch(this.acapy_url + "/wallet/did", requestOptions);
  
      // Check if the response is OK (status code 200-299)
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
  
      // Parse the response as JSON
      const result = await response.json();
      
  
      return result.results; // Return the parsed JSON result
    } catch (error) {
      console.error("Error during wallet creation:", error);
      throw error; // Re-throw the error so it can be caught elsewhere if needed
    }
  }
  //create schema
  async getSchemas() {
    
    const token = await this.#walletToken;
    var requestOptionsForDIDpublicise = {
      method: "GET",
      headers: {
        "accept": "application/json",
        "Content-Type": "application/json", // Make sure to send JSON data
        "Authorization": `Bearer ${token}` // Add the JWT token to the headers
      },
      redirect: "follow",
    };
    
    const schemaRes = await fetch(this.acapy_url + "/anoncreds/schemas" , requestOptionsForDIDpublicise);
    
    return await schemaRes.json();
  }
  async getSchemaProperties(schemaId) {
    const token = await this.#walletToken;
    var requestOptionsForDIDpublicise = {
      method: "GET",
      headers: {
        "accept": "application/json",
        "Content-Type": "application/json", // Make sure to send JSON data
        "Authorization": `Bearer ${token}` // Add the JWT token to the headers
      },
      redirect: "follow",
    };
    
    const schemaRes = await fetch(this.acapy_url + "/anoncreds/schema/" + schemaId , requestOptionsForDIDpublicise);
    
    return await schemaRes.json();
  }
  async createSchema(properties) {
    /*
    properties object:
    "schema": {
    "attrNames": [
      "score", //more props can be added
          ],
    "name": "Example schema", //schema name
    "version": "1.0" //schema version
    }
    */
    //first try to find a did with endorser, steward or trustee role.
    //if not found, then throw an error
    //if found, then create schema using that DID
    let dids = await this.listDIDs();
    let selectedDid = null;

    const token = await this.#walletToken;

const requestOptions = {
  method: "GET",
  headers: {
    "accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": `Bearer ${token}`
  },
  redirect: "follow",
};

// Create an array of promises
const promises = dids.map(async element => {
  const response = await fetch(`${this.acapy_url}/ledger/get-nym-role?did=${element.did}`, requestOptions);
  if (!response.ok) return null;
  const result = await response.json();
  if (["TRUSTEE", "STEWARD", "ENDORSER"].includes(result.role)) {
    return {
      did: element.did,
      verkey: element.verkey,
      role: result.role
    };
  }
  return null;
});

// Wait for all promises to resolve
const results = await Promise.all(promises);

// Filter out null results and select the first valid one
const validResult = results.find(res => res !== null);

if (validResult) {
  selectedDid = validResult.did;
}
else {
  return new Error("No valid DID found with the required role");
}

//set did as public DID.
var requestOptionsForDIDpublicise = {
  method: "POST",
  headers: {
    "accept": "application/json",
    "Content-Type": "application/json", // Make sure to send JSON data
    "Authorization": `Bearer ${token}` // Add the JWT token to the headers
  },
  redirect: "follow",
};



await fetch(this.acapy_url + "/wallet/did/public?did=" + selectedDid, requestOptionsForDIDpublicise);

//select the first valid DID as issuer DID
properties.schema["issuerId"] = selectedDid;
  
console.log(properties);
// Define the request options
var requestOptionsForSchema = {
  method: "POST",
  headers: {
    "accept": "application/json",
    "Content-Type": "application/json", // Make sure to send JSON data
    "Authorization": `Bearer ${token}` // Add the JWT token to the headers
  },
  body: JSON.stringify(properties),
  redirect: "follow",
};



// Await the fetch call and parse the response as JSON
const response = await fetch(this.acapy_url + "/anoncreds/schema", requestOptionsForSchema);

// Check if the response is OK (status code 200-299)
if (!response.ok) {
  throw new Error(`HTTP error! status: ${response.status}`);
}

// Parse the response as JSON
const result = await response.json();
return result.schema_state.schema_id;
  }
  async getCredentialDefinitions(schemaId){
    //get schema seqNo 

    
    var token = await this.#walletToken;
    var requestOptForSchemaSeqNo = {
      method: "GET",
      headers: {
        "accept": "application/json",
        "Content-Type": "application/json", // Make sure to send JSON data
        "Authorization": `Bearer ${token}` // Add the JWT token to the headers
      },
      redirect: "follow",
    };
    var resOfSchemaSeq = await fetch(this.acapy_url + '/anoncreds/schema/'+ schemaId,requestOptForSchemaSeqNo);
    if (!resOfSchemaSeq.ok) {
      throw new Error(`NO SUCH SCHEMA EXISTS ON THIS WALLET`);
    }
    var resjson = await resOfSchemaSeq.json();
    var schemaSeqNo = resjson.schema_metadata.seqNo;
    var requestOptionsForCredDef = {
      method: "GET",
      headers: {
        "accept": "application/json",
        "Content-Type": "application/json", // Make sure to send JSON data
        "Authorization": `Bearer ${token}` // Add the JWT token to the headers
      },
      redirect: "follow",
    };
    var response = await fetch(this.acapy_url + "/anoncreds/credential-definitions", requestOptionsForCredDef);

    

    if (!response.ok) {
      console.log(schemaId)
      if(response.status == 401){
        //if unauthorised, get token again then run function again.
        this.#getExistingWalletJWT();
        this.getCredentialDefinitions(schemaId);
      }
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const result = await response.json();

    var credDefIDs = result.credential_definition_ids;
    //selected schemas credDefID will be found here.

    var requestOpt = {
      method: "GET",
      headers: {
        "accept": "application/json",
        "Content-Type": "application/json", // Make sure to send JSON data
        "Authorization": `Bearer ${token}` // Add the JWT token to the headers
      },
      redirect: "follow",
    }
    for (const element of credDefIDs){
      var response = await fetch(this.acapy_url + "/anoncreds/credential-definition/" + element, requestOpt);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      var s = await response.json();
      if(s.credential_definition.schemaId == schemaSeqNo) {
        return s.credential_definition_id ;
      }
      
    }

    return null;
  }
  async createCredentialDefinition(properties) {
    //the incoming object expects an issuer DID, first get the list of DIDs then filter for the one with STEWARD or TRUSTEE role.
    let dids = await this.listDIDs();
    let selectedDid = null;

    const token = await this.#walletToken;

const requestOptions = {
  method: "GET",
  headers: {
    "accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": `Bearer ${token}`
  },
  redirect: "follow",
};

// Create an array of promises
const promises = dids.map(async element => {
  const response = await fetch(`${this.acapy_url}/ledger/get-nym-role?did=${element.did}`, requestOptions);
  if (!response.ok) return null;
  const result = await response.json();
  if (["TRUSTEE", "STEWARD", "ENDORSER"].includes(result.role)) {
    return {
      did: element.did,
      verkey: element.verkey,
      role: result.role
    };
  }
  return null;
});

// Wait for all promises to resolve
const results = await Promise.all(promises);

// Filter out null results and select the first valid one
const validResult = results.find(res => res !== null);

if (validResult) {
  selectedDid = validResult.did;
}
else {
  return new Error("No valid DIDs exist in wallet, (NO STEWARD/TRUSTEE/ENDORSER IN WALLET)");
}

//set did as public DID.
var requestOptionsForDIDpublicise = {
  method: "POST",
  headers: {
    "accept": "application/json",
    "Content-Type": "application/json", // Make sure to send JSON data
    "Authorization": `Bearer ${token}` // Add the JWT token to the headers
  },
  redirect: "follow",
};



await fetch(this.acapy_url + "/wallet/did/public?did=" + selectedDid, requestOptionsForDIDpublicise);

//select the first valid DID as issuer DID
properties.credential_definition["issuerId"] = selectedDid;

//now we can create the credential definition.
// Define the request options
var requestOptionsForCredDef = {
  method: "POST",
  headers: {
    "accept": "application/json",
    "Content-Type": "application/json", // Make sure to send JSON data
    "Authorization": `Bearer ${token}` // Add the JWT token to the headers
  },
  body: JSON.stringify(properties),
  redirect: "follow",
};
var response = await fetch(this.acapy_url + "/anoncreds/credential-definition", requestOptionsForCredDef);

// Check if the response is OK (status code 200-299)
if (!response.ok) {
  throw new Error(`HTTP error! status: ${response.status}`);
}

// Parse the response as JSON
const result = await response.json();
return result;
  }
  async connect(goal,goal_code,alias,label,multiUse,requesterUrl) {
    //connect function is a flow..
    /*
      Firstly connect function creates an out-of-band request for the browser wallet with auto_accept set to true.
      Then the browser wallet will open a popup window with the request, and the user will either accept or decline the request.
      When the user accepts the request, the browser extension wallet will send a out-of-band receive_invitation message to the aca-py instance.
      After doing this, both parties will call /connections/connectionID endpoint with their received connection ID's, and check  "state": "active", if not, there is an issue. 
      Protocol: https://github.com/hyperledger/aries-rfcs/blob/main/features/0434-outofband/README.md
    */
    //generate out-of-band request.
    
    var request = {
      "accept": [
        "didcomm/aip1",
        "didcomm/aip2;env=rfc19"
      ],
      "alias": alias,
      "goal": goal,
      "goal_code": goal_code,
      "handshake_protocols": [
        "https://didcomm.org/didexchange/1.0"
      ],
      "my_label": label,
      "use_public_did": false,
      "protocol_version": "1.1",
    }

    var res = await this.#outOfBandProtocol(request, multiUse || false);

    //the response will have a field called invitation, we have to open a popup with this invitation.
    //open a popup with the invitation.
    //first create the data.
    var requestData = {
      invitation : res.invitation,
      requesterUrl : requesterUrl,
    }

    this.#invi_msg_id = res.invi_msg_id;
    console.log(this.#invi_msg_id)
    return requestData;
  }
  async issueCredential(properties) {
    var schema = await this.#getSchema(properties.schemaId);
    
    var invi_msg_id = this.#invi_msg_id;
    console.log("invi_msg_id", invi_msg_id);
    if(invi_msg_id == null) {
      throw new Error('No connection established, connect flow must be completed first.');
    }
    var conn = await this.#getConnectionFromInvitationMsgID(invi_msg_id);

    //conn is an array of objects.
    console.log(conn)
    conn = conn.results[0];
    if(conn == null || conn.state != "active") {
      throw new Error('Connection not established, connect flow must be completed first.');
    }
    console.log(properties);
    var requestObject = {
      "auto_issue": true,
      "auto_remove": true,
      "comment": properties.comment,
      "connection_id": conn.connection_id,
      "credential_preview": {
        "@type": "issue-credential/2.0/credential-preview",
        "attributes": properties.attributes
      },
      "filter": {
        "anoncreds": {
          "cred_def_id": properties.credDefId,
          "schema_id": properties.schemaId,
          "schema_name": schema.schemaName,
          "schema_version": schema.schemaVersion
        },
      }
    }

    //with connection ID, we can start the credential dance
    var token = await this.#walletToken;
    //request path= issue-credential-2.0/send-offer
    const requestOptions = {
      method: "POST",
      headers: {
        "accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify(requestObject),
      redirect: "follow",
    };

    var response = await fetch(this.acapy_url + "/issue-credential-2.0/send-offer", requestOptions);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    response = await response.json();
    return response;

  }
  async createProofRequest(properties) {
    console.log(this.#walletToken);
    /*
    Properties will have requested attributes and requested predicates.
    Connection ID will come from the connection established with the browser wallet, we will get it from invi_msg_id.
  
    /present-proof-2.0/send-request
{
    "auto_remove": true,
    "auto_verify": false,
    "comment": "string",
    "connection_id": "9ee8acd7-33f6-4536-a525-e368dd270d69",
    "presentation_request": {
        "indy": {
            "name": "Proof request",
            "nonce": "1",
            "requested_attributes": {
                "ssn": {
                    "name": "ssn",
                    "restrictions": [
                        {
                            "cred_def_id": "WcwnxihsS8s1RqcNkVnfBr:3:CL:46:default",
                            "attr::ssn::value": "123456-1234"
                        }
                    ]
                }
            },
            "requested_predicates": {},
            "version": "1.0"
        }
    },
    "trace": false
}
    */

//first get the connection ID

var invi_msg_id = this.#invi_msg_id;
console.log(invi_msg_id);
if(invi_msg_id == null) {
  throw new Error('No connection established, connect flow must be completed first.');
}
  var conn = await this.#getConnectionFromInvitationMsgID(invi_msg_id);
  //conn is an array of objects.
  conn = conn.results[0];
  if(conn == null || conn.state != "active") {
    throw new Error('Connection not established, connect flow must be completed first.');
  }
  console.log(properties);
  var requestObject = {
    "auto_remove": true,
    "auto_verify": false,
    "comment": "string",
    "connection_id": conn.connection_id,
    "presentation_request": {
        "anoncreds": {
            "name": "Proof request",
            "nonce": "1",
            "requested_attributes": properties.attributes,
            "requested_predicates": properties.predicates,
            "version": "1.0"
        }
    },
    "trace": false
  }

  //send request to aca-py

  var token = await this.#walletToken;
  //path = /present-proof-2.0/send-request

  const requestOptions = {
    method: "POST",
    headers: {
      "accept": "application/json",
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`
    },
    body: JSON.stringify(requestObject),
    redirect: "follow",
  };

  var res = await fetch(this.acapy_url + "/present-proof-2.0/send-request", requestOptions);
  if (!res.ok) {
    throw new Error(`HTTP error! status: ${res.status}`);
  }
  res = await res.json();
  console.log(res);
  
  return res;

  }
  async verifyProof() {

    //endpoint: /present-proof-2.0/records/{pres_ex_id}/verify-presentation

    try{
       var token = await this.#walletToken;
      var conn = await this.#getConnectionFromInvitationMsgID(this.#invi_msg_id);
      conn = conn.results[0];
      var getPresExIdHeaders = {
        method: "GET",
        headers: {
          "accept": "application/json",
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        redirect: "follow",
      };
      var presExId = await fetch(this.acapy_url + "/present-proof-2.0/records?connection_id="+conn.connection_id, getPresExIdHeaders);
      if (!presExId.ok) {
        throw new Error(`HTTP error! status: ${presExId.status}`);
      }
      presExId = await presExId.json();
      console.log(presExId);
      presExId = presExId.results[0].pres_ex_id;
  
      var verifyPresentationHeaders = {
        method: "POST",
        headers: {
          "accept": "application/json",
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        redirect: "follow",
      };
  
      var response = await fetch(this.acapy_url + "/present-proof-2.0/records/"+presExId+"/verify-presentation", verifyPresentationHeaders);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      response = await response.json();
      console.log(response);
      return response;
  

    }
    catch (ex) {
      return ex;

    }
   
  }

  //private methods
  async #initialiseWalletInstanceWithoutMnemonic() {
    const mnemonic = bip39.generateMnemonic(englishWordlist );
                const seed = bip39.mnemonicToSeedSync(mnemonic).slice(0,32);
                //from seed generate wallet name and key / just random parts of the seed
                var walletKey = seed.slice(0,32);
                var walletName = seed.slice(16,26);
                var walletName = this.#getPublicWalletName(walletName.toString());
                const base58Key = await this.#generateBase58Key(walletKey);
                const res = await this.#generateNewWallet({
                            "key_management_mode": "managed",
                            "label": walletName,
                            "wallet_dispatch_type": "default",
                            "wallet_key": base58Key,
                            "wallet_key_derivation": "RAW",
                            "wallet_name": walletName,
                            "wallet_type": "askar-anoncreds"});
                //generated seed will be used in a request to Aca-py
                var wallet_id = res.wallet_id;
                var token = res.token;
                this.#walletToken = token;
                this.#walletKey = walletKey;
                this.#walletName = walletName;
                this.#walletId = wallet_id;
                return {mnemonic: mnemonic,walletID: wallet_id, walletToken: token, walletKey: walletKey, walletName: walletName};
  }
  async #initialiseWalletInstanceWithMnemonic(mnemonic){
    //if wallet exists in aca-py, then just open it
    //if wallet does not exist, then create a new wallet
    const seed = bip39.mnemonicToSeedSync(mnemonic).slice(0,32);
    //from seed generate wallet name and key / just random parts of the seed
    var walletKey = seed.slice(0,32);
    var walletName = seed.slice(16,26);
    var walletName = this.#getPublicWalletName(walletName.toString());
    this.#walletKey = walletKey;
    this.#walletName = walletName;
    const base58Key = await this.#generateBase58Key(walletKey);
    try {
      
      const res = await this.#getExistingWalletJWT();
      var wallet_id = res.wallet_id;
      var token = res.token;
      this.#walletId = wallet_id;
      this.#walletToken = token;
      return {walletID: wallet_id, walletToken: token, walletKey: walletKey, walletName: walletName};
    }
    catch (error) {
      const res = await this.#generateNewWallet({
        "key_management_mode": "managed",
        "label": walletName,
        "wallet_dispatch_type": "default",
        "wallet_key": base58Key,
        "wallet_key_derivation": "RAW",
        "wallet_name": walletName,
        "wallet_type": "askar-anoncreds"});
        var wallet_id = res.wallet_id;
    var token = res.token;
    this.#walletToken = token;
    this.#walletKey = walletKey;
    this.#walletName = walletName;
    this.#walletId = wallet_id;
    
    var dids = await this.listDIDs();
    
    if(dids.length == 0) {
      await this.generateNewDID();
    }

    return {walletID: wallet_id, walletToken: token, walletKey: walletKey, walletName: walletName};
    }
    
    
  }
  #getPublicWalletName(walletKey) {
    // Create a SHA-256 hash of the walletKey using crypto-js
    const hash = CryptoJS.SHA256(walletKey).toString(CryptoJS.enc.Hex);
    
    // Return a truncated version (e.g., first 12 characters) to use as wallet name
    return `wallet-${hash.slice(0, 12)}`; // Prefix with 'wallet-' to make it identifiable
  }
  // Function to generate a Base58-encoded key from 32-byte raw data
  async #generateBase58Key(walletKey){
    // Ensure the walletKey is exactly 32 characters long
    if (walletKey.length !== 32) {
      throw new Error('walletKey must be exactly 32 characters long');
    }
  
    // Convert the walletKey string into a byte array (use 'latin1' or 'hex' if it's meant to be raw bytes)
    const keyBytes = Buffer.from(walletKey, 'latin1'); // 'latin1' treats it as raw bytes
  
    // Encode the key using Base58
    const base58Key = bs58.encode(keyBytes);
  
    return base58Key.toString(); // Return the Base58-encoded key
  };
  async #generateNewWallet(request) {
    // Convert the request object to a JSON string
    var raw = JSON.stringify(request);
  
    // Define the request options
    var requestOptions = {
      method: "POST",
      headers: {
        "accept": "application/json",
        "Content-Type": "application/json", // Make sure to send JSON data
      },
      body: raw,
      redirect: "follow",
    };
  
    try {
      // Await the fetch call and parse the response as JSON
      const response = await fetch(this.acapy_url + "/multitenancy/wallet", requestOptions);
  
      // Check if the response is OK (status code 200-299)
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
  
      // Parse the response as JSON
      const result = await response.json();
      
  
      return result; // Return the parsed JSON result
    } catch (error) {
      console.error("Error during wallet creation:", error);
      throw error; // Re-throw the error so it can be caught elsewhere if needed
    }
  }
  async #getExistingWalletJWT() {
    // Convert the request object to a JSON string
  
    // Define the request options
    var requestOptions = {
      method: "GET",
      headers: {
        "accept": "application/json",
        "Content-Type": "application/json", // Make sure to send JSON data
      },
      redirect: "follow",
    };
  
    try {
      // Await the fetch call and parse the response as JSON
      const response = await fetch(this.acapy_url + "/multitenancy/wallets?wallet_name=" + this.#walletName , requestOptions);
  
      // Check if the response is OK (status code 200-299)
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
  
      // Parse the response as JSON
      const result = await response.json();
      
      const wallet_key = await this.#generateBase58Key(this.#walletKey);
      const jwt = await this.#getJWT({ wallet_key: wallet_key},result.results[0].wallet_id);
  
      return {wallet_id: result.results[0].wallet_id, token: jwt.token}; // Return the parsed JSON result
    } catch (error) {
      console.error("Error during wallet creation:", error);
      throw error; // Re-throw the error so it can be caught elsewhere if needed
    }
  }
  async #getJWT(request,wallet_id) {
    // Convert the request object to a JSON string
    var raw = JSON.stringify(request);
  
    // Define the request options
    var requestOptions = {
      method: "POST",
      headers: {
        "accept": "application/json",
        "Content-Type": "application/json", // Make sure to send JSON data
      },
      body: raw,
      redirect: "follow",
    };
  
    try {
      // Await the fetch call and parse the response as JSON
      const response = await fetch(this.acapy_url+ "/multitenancy/wallet/" + wallet_id + '/token', requestOptions);
  
      // Check if the response is OK (status code 200-299)
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
  
      // Parse the response as JSON
      const result = await response.json();
      
  
      return result; // Return the parsed JSON result
    } catch (error) {
      console.error("Error during wallet creation:", error);
      throw error; // Re-throw the error so it can be caught elsewhere if needed
    }
  }
  async #outOfBandProtocol(request,multiUse) {
    //does not work when multiUse is true ? check with aca-py devs idk
    if(this.#walletToken == null || this.#walletId == null) {
      throw new Error('Wallet not initialised, initialiseWalletInstance(withOrWithoutMnemonic) must be called first');
    }
    try {
      // Wait for the token to be retrieved from storage
      const token = this.#walletToken;
  
      // Define the request options
      var requestOptions = {
        method: "POST",
        headers: {
          "accept": "application/json",
          "Content-Type": "application/json", // Make sure to send JSON data
          "Authorization": `Bearer ${token}` // Add the JWT token to the headers
        },
        body : JSON.stringify(request),
        redirect: "follow",
      };
  
      // Await the fetch call and parse the response as JSON
      const response = await fetch(this.acapy_url+ "/out-of-band/create-invitation?auto_accept=true&multi_use="+multiUse, requestOptions);
  
      // Check if the response is OK (status code 200-299)
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
  
      // Parse the response as JSON
      const result = await response.json();
      
  
      return result; // Return the parsed JSON result
    } catch (error) {
      console.error("Error during DID creation:", error);
      throw error; // Re-throw the error so it can be caught elsewhere if needed
    }
  }
  async #getConnectionFromInvitationMsgID(msg_id) {
    // Wait for the token to be retrieved from storage
    const token = this.#walletToken;

    // Define the request options
    var requestOptions = {
      method: "GET",
      headers: {
        "accept": "application/json",
        "Content-Type": "application/json", // Make sure to send JSON data
        "Authorization": `Bearer ${token}` // Add the JWT token to the headers
      },
      redirect: "follow",
    };

    // Await the fetch call and parse the response as JSON
    const response = await fetch(this.acapy_url + "/connections?invitation_msg_id="+msg_id, requestOptions);

    // Check if the response is OK (status code 200-299)
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    // Parse the response as JSON
    const result = await response.json();
    console.log(result);
    return result;
  }
  async #getSchema(schemaId) {
    // Wait for the token to be retrieved from storage
    const token = this.#walletToken;

    // Define the request options
    var requestOptions = {
      method: "GET",
      headers: {
        "accept": "application/json",
        "Content-Type": "application/json", // Make sure to send JSON data
        "Authorization": `Bearer ${token}` // Add the JWT token to the headers
      },
      redirect: "follow",
    };

    // Await the fetch call and parse the response as JSON
    const response = await fetch(this.acapy_url + "/anoncreds/schema/" + schemaId, requestOptions);

    // Check if the response is OK (status code 200-299)
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    // Parse the response as JSON
    const result = await response.json();
    return {schemaName: result.schema.schema_name, schemaVersion: result.schema.schema_version};
  }
  async #makeDidPublic(did) {
    const token = this.#walletToken;

    // Define the request options
    var requestOptions = {
      method: "POST",
      headers: {
        "accept": "application/json",
        "Content-Type": "application/json", // Make sure to send JSON data
        "Authorization": `Bearer ${token}` // Add the JWT token to the headers
      },
      redirect: "follow",
    };

    // Await the fetch call and parse the response as JSON
    const response = await fetch(this.acapy_url + "/wallet/did/public?did=" + did, requestOptions);

    // Check if the response is OK (status code 200-299)
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    // Parse the response as JSON
    const result = await response.json();
    return result;
  }
}

  
