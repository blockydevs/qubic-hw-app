import qubic from "@qubic-lib/qubic-ts-library";
import type { IQubicTransaction } from "./types";
import { TRANSACTION_BYTES_LENGTH } from "./constants";

export const convertDerivationPathToBuffer = (
    derivationPath: string // The "derivationPath" is following the BIP44 standard (https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#path-levels)
) => {
    const split = derivationPath.split("/");

    if (split[0] !== "m") {
        throw new Error("Error master expected");
    }

    const parts = split.slice(1);

    let derivationPathBuffer = Buffer.alloc(0);

    for (const value of parts) {
        if (value === "") {
            throw new Error(`Error missing value in split list "${split}"`);
        }

        let num: number;

        // BIP-32 hardened derivation:
        // The apostrophe (') marks an index as hardened by setting the highest bit (0x80000000).
        // Hardened derivation requires the parent private key, providing extra security by preventing
        // child key derivation from the parent public key alone.
        if (value.endsWith("'")) {
            num = parseInt(value.slice(0, -1), 10);
            num |= 0x80000000; // Apply BIP32 hardening
        } else {
            num = parseInt(value, 10);
        }

        const componentBuffer = Buffer.alloc(4);
        componentBuffer.writeUInt32BE(num >>> 0, 0); // >>> 0 ensures unsigned
        derivationPathBuffer = Buffer.concat([
            derivationPathBuffer,
            componentBuffer,
        ]);
    }

    const derivationPathLength = Buffer.alloc(1, parts.length); // First byte is count of path components

    return Buffer.concat([derivationPathLength, derivationPathBuffer]);
};

export const getPlainTransactionBytes = (
    transaction: IQubicTransaction
): Buffer => {
    const packetSize =
        transaction.getPackageSize() - transaction.payload.getPackageSize();

    const builder = new qubic.QubicPackageBuilder(packetSize);

    builder.add(transaction.sourcePublicKey);
    builder.add(transaction.destinationPublicKey);
    builder.add(transaction.amount);
    builder.addInt(transaction.tick);
    builder.addShort(transaction.inputType);
    builder.addShort(transaction.inputSize);

    const transactionBytes = builder.getData(); // transactionBytes is 144 bytes long, where 64 is reserved for signature (which is here empty, builder not signed).

    return Buffer.from(transactionBytes.subarray(0, TRANSACTION_BYTES_LENGTH));
};
