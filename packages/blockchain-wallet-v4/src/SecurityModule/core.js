export default ({ BIP39, Bitcoin, crypto, ed25519, EthHd }) => {
  const credentialsEntropy = ({ guid, password, sharedKey }) =>
    crypto.sha256(Buffer.from(guid + sharedKey + password))

  const entropyToSeed = entropy =>
    BIP39.mnemonicToSeed(BIP39.entropyToMnemonic(entropy))

  const deriveBIP32KeyFromSeedHex = ({ entropy, network }, path) => {
    const seed = entropyToSeed(entropy)

    return Bitcoin.HDNode.fromSeedBuffer(seed, network)
      .derivePath(path)
      .toBase58()
  }

  // Derivation error using seedHex directly instead of seed derived from
  // mnemonic derived from seedHex
  const deriveLegacyEthereumKey = ({ entropy }) =>
    EthHd.fromMasterSeed(entropy)
      .derivePath(`m/44'/60'/0'/0/0`)
      .getWallet()
      .getPrivateKey()

  const deriveSLIP10ed25519Key = async ({ entropy }, path) => {
    const seed = entropyToSeed(entropy)
    return ed25519.derivePath(path, seed.toString(`hex`))
  }

  const generateMatomoUserId = ({ seedHex }) => {
    const mnemonic = BIP39.entropyToMnemonic(seedHex)
    const masterhex = BIP39.mnemonicToSeed(mnemonic)
    const masterHDNode = Bitcoin.HDNode.fromSeedBuffer(masterhex)
    let hash = crypto.sha256('info.blockchain.matomo')
    let purpose = hash.slice(0, 4).readUInt32BE(0) & 0x7fffffff
    return masterHDNode.deriveHardened(purpose).getAddress()
  }

  return {
    credentialsEntropy,
    deriveBIP32KeyFromSeedHex,
    deriveLegacyEthereumKey,
    deriveSLIP10ed25519Key,
    entropyToSeed,
    generateMatomoUserId
  }
}
