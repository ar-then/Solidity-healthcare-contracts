# Solidity contracts for healthcare


## Consent management tool v.0.0.1

A patient can use blockchain to secure access to the medical records URIs 

Using the smart contract functions, a patient can:
1. Create an onchain pointer that secures access to the medical record, limiting it to the record's owner (a patient)
2. Fetch the record at any time using the onchain pointer
3. Modify, update, or delete the record based on the new information
4. Grant temporary access to medical operators to perform these actions and revoke it at any time

A smart contract can be deployed using the script.

Only the patient and the authorized entities can access the record. No one, except the patient, can update or delete it, and the patient can revoke access at any time. It secures patient data, minimizes the risk of manipulation, and significantly reduces operational costs.

Note: Realizing these contracts on Ethereum requires large expenses due to the gas fees. Using other EVM blockchains (such as Arbitrum or Polygon) or those optimized specifically for record storage is recommended.
