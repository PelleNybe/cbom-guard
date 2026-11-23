import crypto from "node:crypto";
import jwt from "jsonwebtoken";

export function vulnerableJsCrypto() {
  // Comment: crypto.createHash("md5") must be ignored
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const legacyHash = crypto.createHash("sha1").update("data").digest("hex");
  const legacyCipher = crypto.createCipheriv("des-ede3", Buffer.alloc(24), Buffer.alloc(8));
  const token = jwt.sign({ sub: "user" }, privateKey, { algorithm: "RS256" });
  const safeHash = crypto.createHash("sha384").update("ok").digest("hex");
  return { publicKey, legacyHash, legacyCipher, token, safeHash };
}
