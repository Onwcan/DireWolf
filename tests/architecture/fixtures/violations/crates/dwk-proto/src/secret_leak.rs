// Violation fixture (M4e, TX030): a value type in the public wire contract.
pub struct ToolResultWithCredential {
    pub handle: String,
    pub value: SecretMaterial,
    pub pipe: SecretPipe,
}

pub fn plaintext(material: &SecretMaterial) -> &[u8] {
    let _buffer: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    material.expose()
}
