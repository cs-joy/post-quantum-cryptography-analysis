// migrations/1_deploy_contracts.js
const PQCVerifier = artifacts.require("PQCVerifier");

module.exports = function(deployer) {
  deployer.deploy(PQCVerifier);
};