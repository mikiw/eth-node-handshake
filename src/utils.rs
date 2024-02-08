// TODO: aes-ctr is deprecated, move this info to doc from code
pub type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;
pub type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;
