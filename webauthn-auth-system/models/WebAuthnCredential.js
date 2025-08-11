import mongoose from 'mongoose';

const WebAuthnCredentialSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  credentialID: { type: Buffer, required: true },
  credentialPublicKey: { type: Buffer, required: true },
  counter: { type: Number, required: true },
}, { timestamps: true });

export default mongoose.model('WebAuthnCredential', WebAuthnCredentialSchema);
