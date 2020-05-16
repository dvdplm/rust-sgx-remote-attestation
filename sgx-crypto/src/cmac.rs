use mbedtls::cipher::raw::{Cipher, CipherId, CipherMode};

pub const MAC_LEN: usize = 16;
pub type MacTag = [u8; MAC_LEN];

/// 128-bit AES-CMAC
pub struct Cmac {
    inner: Cipher,
    key: [u8; MAC_LEN], 
}

impl Cmac {
    pub fn new(key: &[u8]) -> super::Result<Self> {
        let mut _key = [0u8; MAC_LEN];
        _key.as_mut().clone_from_slice(key);
        Ok(Self {
            inner: Cipher::setup(CipherId::Aes, CipherMode::ECB, (MAC_LEN*8) as u32)?,
            key: _key,
        })
    }

    pub fn sign(&mut self, data: &[u8]) -> super::Result<MacTag> {
        let mut tag = [0u8; MAC_LEN];
        self.inner.cmac(self.key.as_ref(), data, tag.as_mut())?;
        Ok(tag)
    }

    pub fn verify(&mut self, data: &[u8], tag: &MacTag) -> super::Result<()> {
        let ref_tag = self.sign(data)?;
        match &ref_tag == tag {
            true => Ok(()),
            false => Err(super::error::CryptoError::CmacVerificationError),
        }
    } 
}


//use crypto_mac::Mac as InnerMacTrait;
//use cmac::Cmac as InnerCmac;
//use aes::Aes128;

//pub type MacError = crypto_mac::MacError;
//pub type MacTag = [u8; MAC_LEN];

//pub struct Cmac {
    //key: [u8; MAC_LEN], 
//}

//impl Cmac {
    //pub fn new(key: &[u8; MAC_LEN]) -> Self {
        //Self {
            //key: *key,
        //}
    //}

    //pub fn sign(&self, data: &[u8]) -> MacTag {
        //let mut inner = InnerCmac::<Aes128>::new_varkey(&self.key[..]).unwrap();
        //inner.input(data);
        //let mac = inner.result_reset();
        //mac.code().into()
    //}

    //pub fn verify(&self, data: &[u8], tag: &MacTag) -> Result<(), MacError>{
        //let mut inner = InnerCmac::<Aes128>::new_varkey(&self.key[..]).unwrap();
        //inner.input(data);
        //inner.verify(&tag[..])
    //} 
//}
