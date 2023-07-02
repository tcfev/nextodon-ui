
import * as ethers from "ethers";

function hexToBytes(hex: string): number[] {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

function postData(url: string, data: any): Promise<Response> {
    const response = fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(data),
    });
    return response;
}

export function words(): string[] {
    const en = ethers.wordlists['en'] as ethers.WordlistOwl;

    return en._decodeWords();
}

export async function login(mnemonic: string, passphrase: string): Promise<string | null> {
    const mnemonicObject = ethers.Mnemonic.fromPhrase(mnemonic, passphrase);
    console.log(mnemonicObject)
    const node = ethers.HDNodeWallet.fromMnemonic(mnemonicObject);
    const wallet = node.derivePath("m/44'/60'/0'/0/0");
    const digest = ethers.sha256(wallet.publicKey);
    const signingKey = new ethers.SigningKey(wallet.privateKey);
    const signature = signingKey.sign(digest);
    const r = hexToBytes(signature.r.substring(2));
    const s = hexToBytes(signature.s.substring(2));

    const signatureBytes = [0x30, 0x44, 0x02, 0x20];
    signatureBytes.push(...r);
    signatureBytes.push(...[0x02, 0x20]);
    signatureBytes.push(...s);

    const publicKeyBytes = hexToBytes(wallet.publicKey.substring(2));

    const sig = Uint8Array.from(signatureBytes);
    const pub = Uint8Array.from(publicKeyBytes);

    const signature64 = ethers.encodeBase64(sig);
    const publicKey64 = ethers.encodeBase64(pub);

    const response = await postData("/api/v1/authentication/signin", {
        signature: signature64,
        publicKey: publicKey64,
    });
    const result = await response.json();

    return result.value;
}

export function generateMnemonic(): string[] {
    return ethers.Mnemonic.fromEntropy(ethers.randomBytes(16), this).phrase.split(' ');
}
