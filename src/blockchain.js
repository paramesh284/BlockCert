import { readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import solc from "solc";
import ganache from "ganache";
import { BrowserProvider, Contract, ContractFactory } from "ethers";

const DEMO_MNEMONIC = "test test test test test test test test test test test junk";
const OWNER_ACCOUNT_PATH = "m/44'/60'/0'/0/0";
const CHAIN_ID = 31337;
const CHAIN_ID_HEX = "0x7a69";

function compileRegistry(contractFile) {
    const source = readFileSync(contractFile, "utf8");
    const input = {
        language: "Solidity",
        sources: {
            "CertificateRegistry.sol": {
                content: source
            }
        },
        settings: {
            optimizer: {
                enabled: true,
                runs: 200
            },
            evmVersion: "shanghai",
            outputSelection: {
                "*": {
                    "*": ["abi", "evm.bytecode.object"]
                }
            }
        }
    };
    const result = JSON.parse(solc.compile(JSON.stringify(input)));
    const errors = (result.errors ?? []).filter(error => error.severity === "error");

    if (errors.length > 0) {
        throw new Error(`Unable to compile the certificate registry:\n${errors.map(error => error.formattedMessage).join("\n")}`);
    }

    const compiled = result.contracts?.["CertificateRegistry.sol"]?.CertificateRegistry;

    if (!compiled?.evm.bytecode.object) {
        throw new Error("Solidity compiled without producing a certificate registry contract.");
    }

    return {
        abi: compiled.abi,
        bytecode: `0x${compiled.evm.bytecode.object}`
    };
}

export async function startLocalBlockchain({ dataDirectory, contractFile, quiet = true }) {
    await mkdir(dataDirectory, { recursive: true });
    const chainDirectory = path.join(dataDirectory, "chain");
    const deploymentFile = path.join(dataDirectory, "contract.json");
    const { abi, bytecode } = compileRegistry(contractFile);
    const provider = ganache.provider({
        chain: {
            chainId: CHAIN_ID,
            networkId: CHAIN_ID,
            vmErrorsOnRPCResponse: true
        },
        database: {
            dbPath: chainDirectory
        },
        wallet: {
            mnemonic: DEMO_MNEMONIC,
            hdPath: OWNER_ACCOUNT_PATH,
            totalAccounts: 10,
            defaultBalance: 1000
        },
        miner: {
            blockGasLimit: 12_000_000
        },
        logging: {
            quiet
        }
    });
    const rpcProvider = new BrowserProvider(provider);
    const signer = await rpcProvider.getSigner(0);
    let contractAddress;

    try {
        const savedDeployment = JSON.parse(await readFile(deploymentFile, "utf8"));

        if (savedDeployment.chainId === CHAIN_ID) {
            const bytecodeAtAddress = await rpcProvider.getCode(savedDeployment.address);

            if (bytecodeAtAddress !== "0x") {
                contractAddress = savedDeployment.address;
            }
        }
    } catch (error) {
        if (error.code !== "ENOENT") {
            await provider.disconnect();
            throw new Error(`Unable to read the local contract deployment: ${error.message}`);
        }
    }

    let contract;

    if (contractAddress) {
        contract = new Contract(contractAddress, abi, signer);
    } else {
        const factory = new ContractFactory(abi, bytecode, signer);
        contract = await factory.deploy();
        await contract.waitForDeployment();
        contractAddress = await contract.getAddress();
        await writeFile(
            deploymentFile,
            `${JSON.stringify({ address: contractAddress, chainId: CHAIN_ID }, null, 2)}\n`,
            "utf8"
        );
    }

    return {
        adminAddress: await signer.getAddress(),
        chainId: CHAIN_ID,
        contract,
        contractAddress,
        provider,
        rpcProvider,
        signer
    };
}
