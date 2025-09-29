// This script can be used to deploy the "Storage" contract using ethers.js library.
// Please make sure to compile "./contracts/1_Storage.sol" file before running this script.
// And use Right click -> "Run" from context menu of the file to run the script. Shortcut: Ctrl+Shift+S

import { ethers } from 'ethers'



// Example: grant access (ethers.js)
const contract = new ethers.Contract(address, abi, signer); // signer = patient wallet
const tx = await contract.grantAccess(recordId, providerAddress, Math.floor(Date.now()/1000) + 3600); // 1 hour expiry
await tx.wait();

// Provider fetches URI:
const providerContract = contract.connect(providerSigner);
const uri = await providerContract.getRecordUri(recordId); // will revert if no access
console.log("URI:", uri);
