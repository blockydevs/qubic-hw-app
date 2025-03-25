import type Transport from "@ledgerhq/hw-transport";
import { INS, LEDGER_CLA, P1, P2 } from "./constants";
import type {
    IQubicTransaction,
    ISendToDeviceParams,
    ISignTransactionReturn,
} from "./types";
import {
    convertDerivationPathToBuffer,
    getPlainTransactionBytes,
} from "./utils";
import { schemaSendToDeviceParams } from "./validation";

export class HWAppQubic {
    transport: Transport;

    constructor(transport: Transport) {
        this.transport = transport;
        this.transport.decorateAppAPIMethods(
            this,
            ["getVersion", "getPublicKey", "signTransaction", "signMessage"],
            "",
        );
    }

    async sendToDevice({
        instruction,
        p1,
        p2 = P2.LAST,
        payload = Buffer.alloc(0),
    }: ISendToDeviceParams) {
        const validateParams = schemaSendToDeviceParams.safeParse({
            instruction,
            p1,
            p2,
            payload,
        });

        if (!validateParams.success) {
            throw new Error(validateParams.error.errors[0].message);
        }

        const reply = await this.transport.send(
            LEDGER_CLA,
            instruction,
            p1,
            p2,
            payload,
        );

        return reply.subarray(0, reply.length - 2); // Remove status code
    }

    async getVersion() {
        const [major, minor, patch] = await this.sendToDevice({
            instruction: INS.GET_VERSION,
            p1: P1.START,
        });

        return { version: `${major}.${minor}.${patch}` };
    }

    async getPublicKey(
        derivationPath = "m/44'/1'/0'/0/0",
        withConfirm = false,
    ): Promise<Buffer<ArrayBufferLike>> {
        return await this.sendToDevice({
            instruction: INS.GET_PUBLIC_KEY,
            p1: withConfirm ? P1.CONFIRM : P1.START,
            payload: convertDerivationPathToBuffer(derivationPath),
        });
    }

    async signTransaction(
        derivationPath: string,
        transaction: IQubicTransaction,
    ): Promise<ISignTransactionReturn> {
        const plainTransactionBuffer = Buffer.from(
            getPlainTransactionBytes(transaction),
        );

        const derivationPathBuffer =
            convertDerivationPathToBuffer(derivationPath);

        const payload = Buffer.concat([
            derivationPathBuffer,
            plainTransactionBuffer,
        ]);

        const signatureResponse = await this.sendToDevice({
            instruction: INS.SIGN_TRANSACTION,
            p1: P1.START,
            p2: P2.LAST,
            payload,
        });

        const signature = signatureResponse.subarray(1); // First byte is signature length

        const signedData = Buffer.concat([plainTransactionBuffer, signature]);

        return {
            signature: signature,
            transaction: plainTransactionBuffer,
            signedData,
        };
    }

    async signMessage(message: string) {
        const signature = message;
        const messageHash = message;

        return { signature, messageHash };
    }
}
