## Simple backend service

This service exists so that the wallets mnemonic value does not have to be inside of indy-bex-connector package.

indy-bex-connector package connects to this package and issues/verifies etc. using the mnemonic hardcoded on the index.js
