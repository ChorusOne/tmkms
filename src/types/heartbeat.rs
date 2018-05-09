use signatory::ed25519::{Signature, SIGNATURE_SIZE};
use super::{ValidatorAddress, TendermintSign};
use amino::*;
use hex::encode;
use bytes::{Buf, BufMut};
use std::error::Error;
use std::io::Cursor;


#[derive(PartialEq, Debug)]
pub struct Heartbeat {
    validator_address: ValidatorAddress,
    validator_index: i64,
    height: i64,
    round: i64,
    sequence: i64,
    signature: Option<Signature>,
}

impl TendermintSign for Heartbeat {
    fn cannonicalize(self, chain_id: &str) -> String {
        let value = json!({
            "@chain_id":chain_id,
            "@type":"heartbeat",
            "height":self.height,
            "round":self.round,
            "sequence":self.sequence,
            "validator_address": encode(self.validator_address.0),
            "validator_index": self.validator_index,
            });
        value.to_string()
    }
}

impl Amino for Heartbeat {
    fn serialize(self) -> Vec<u8> {
        let mut buf = vec![];

        let (_, mut pre) = compute_disfix("tendermint/socketpv/SignHeartbeatMsg");
        pre[3] |= typ3_to_byte(Typ3Byte::Typ3_Struct);
        buf.put_slice(pre.as_slice());
        {

//Encode the Validator Address
            encode_field_number_typ3(1, Typ3Byte::Typ3_Struct, &mut buf);
            {
                encode_field_number_typ3(1, Typ3Byte::Typ3_ByteLength, &mut buf);
                amino_bytes::encode(&self.validator_address.0, &mut buf);

                //Encode the validator index
                encode_field_number_typ3(2, Typ3Byte::Typ3_Varint, &mut buf);
                encode_varint(self.validator_index as i64, &mut buf);

                encode_field_number_typ3(3, Typ3Byte::Typ3_8Byte, &mut buf);
                encode_int64(self.height as i64, &mut buf);

                encode_field_number_typ3(4, Typ3Byte::Typ3_Varint, &mut buf);
                encode_varint(self.round as i64, &mut buf);

                encode_field_number_typ3(5, Typ3Byte::Typ3_Varint, &mut buf);
                encode_varint(self.sequence as i64, &mut buf);

                if let Some(sig) = self.signature {
                    let field_prefix = 6 << 3 | typ3_to_byte(Typ3Byte::Typ3_Interface);
                    buf.put(field_prefix);
                    amino_bytes::encode(&sig.0, &mut buf)
                }
            }
            buf.put(typ3_to_byte(Typ3Byte::Typ3_StructTerm));
        }
        buf.put(typ3_to_byte(Typ3Byte::Typ3_StructTerm));


        let mut length_buf = vec![];
        encode_uvarint(buf.len() as u64, &mut length_buf);
        length_buf.append(&mut buf);

        length_buf
    }

    fn deserialize(data: &[u8]) -> Result<Heartbeat, DecodeError> {
        let mut buf = Cursor::new(data);

        {
            let len_field = decode_uvarint(&mut buf)?;
            let data_length = buf.remaining() as u64;

            if data_length != len_field {
                return Err(DecodeError::new("invalid length field"));
            }
        }

        {
            let (_, mut pre) = compute_disfix("tendermint/socketpv/SignHeartbeatMsg");

            pre[3] |= typ3_to_byte(Typ3Byte::Typ3_Struct);
            let mut actual_prefix = pre.clone();
            buf.copy_to_slice(actual_prefix.as_mut_slice());
            if actual_prefix != pre {
                return Err(DecodeError::new("invalid prefix"));
            }
        }
        {
            let typ3 = buf.get_u8();
            let field_prefix = 1 << 3 | typ3_to_byte(Typ3Byte::Typ3_Struct);
            if typ3 != field_prefix {
                return Err(DecodeError::new("invalid type for field 1"));
            }
        }
        {
            let typ3 = buf.get_u8();
            let field_prefix = 1 << 3 | typ3_to_byte(Typ3Byte::Typ3_ByteLength);
            if typ3 != field_prefix {
                return Err(DecodeError::new("invalid type for inner struct field 1"));
            }
        }
        let mut validator_address_array: [u8; 20] = [0; 20];
        validator_address_array.copy_from_slice(amino_bytes::decode(&mut buf)?.as_slice());
        let validator_address = ValidatorAddress(validator_address_array);
        {
            let typ3 = buf.get_u8();
            let field_prefix = 2 << 3 | typ3_to_byte(Typ3Byte::Typ3_Varint);
            if typ3 != field_prefix {
                return Err(DecodeError::new("invalid type for struct field 2"));
            }
        }
        let validator_index = decode_varint(&mut buf)? as i64;
        {
            let typ3 = buf.get_u8();
            let field_prefix = 3 << 3 | typ3_to_byte(Typ3Byte::Typ3_8Byte);
            if typ3 != field_prefix {
                return Err(DecodeError::new("invalid type for struct field 3"));
            }
        }
        let height = decode_int64(&mut buf)?;
        {
            let typ3 = buf.get_u8();
            let field_prefix = 4 << 3 | typ3_to_byte(Typ3Byte::Typ3_Varint);
            if typ3 != field_prefix {
                return Err(DecodeError::new("invalid type for struct field 4"));
            }
        }
        let round = decode_varint(&mut buf)?;

        {
            let typ3 = buf.get_u8();
            let field_prefix = 5 << 3 | typ3_to_byte(Typ3Byte::Typ3_Varint);
            if typ3 != field_prefix {
                return Err(DecodeError::new("invalid type for struct field 5"));
            }
        }
        let sequence = decode_varint(&mut buf)? as i64;
        let mut sig: Option<Signature> = None;

        let mut optional_typ3 = buf.get_u8();

        let sig_field_prefix = 6 << 3 | typ3_to_byte(Typ3Byte::Typ3_Interface);

        if optional_typ3 == sig_field_prefix {
            let mut signature_array: [u8; SIGNATURE_SIZE] = [0; SIGNATURE_SIZE];
            signature_array.copy_from_slice(amino_bytes::decode(&mut buf)?.as_slice());

            sig = Some(Signature(signature_array));

            optional_typ3 = buf.get_u8();
        }
        let struct_term_typ3 = buf.get_u8();
        let struct_end_postfix = typ3_to_byte(Typ3Byte::Typ3_StructTerm);
        if optional_typ3 != struct_end_postfix {
            return Err(DecodeError::new("invalid type for first struct term"));
        }

        if struct_term_typ3 != struct_end_postfix {
            return Err(DecodeError::new("invalid type for second struct term"));
        }


        Ok(Heartbeat {
            validator_address,
            validator_index,
            height,
            round,
            sequence,
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::prelude::*;
    use std::error::Error;

    #[test]
    fn test_serialization() {
        let addr: [u8; 20] = [0xa3, 0xb2, 0xcc, 0xdd, 0x71, 0x86, 0xf1, 0x68, 0x5f, 0x21, 0xf2, 0x48, 0x2a, 0xf4, 0xfb, 0x34, 0x46, 0xa8, 0x4b, 0x35];
        let heartbeat = Heartbeat { validator_address: ValidatorAddress(addr), validator_index: 1, height: 15, round: 10, sequence: 30, signature: None };


        let have = heartbeat.serialize();

        let want = vec![0x2c, 0xbf, 0x58, 0xca, 0xeb, 0xb, 0xa, 0x14, 0xa3, 0xb2, 0xcc, 0xdd, 0x71, 0x86, 0xf1, 0x68, 0x5f, 0x21, 0xf2, 0x48, 0x2a, 0xf4, 0xfb, 0x34, 0x46, 0xa8, 0x4b, 0x35, 0x10, 0x2, 0x19, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xf, 0x20, 0x14, 0x28, 0x3c, 0x4, 0x4];

        assert_eq!(have, want)
    }

    #[test]
    fn test_derialization() {
        let addr: [u8; 20] = [0xa3, 0xb2, 0xcc, 0xdd, 0x71, 0x86, 0xf1, 0x68, 0x5f, 0x21, 0xf2, 0x48, 0x2a, 0xf4, 0xfb, 0x34, 0x46, 0xa8, 0x4b, 0x35];
        let want = Heartbeat { validator_address: ValidatorAddress(addr), validator_index: 1, height: 15, round: 10, sequence: 30, signature: None };

        let data = vec![0x2c, 0xbf, 0x58, 0xca, 0xeb, 0xb, 0xa, 0x14, 0xa3, 0xb2, 0xcc, 0xdd, 0x71, 0x86, 0xf1, 0x68, 0x5f, 0x21, 0xf2, 0x48, 0x2a, 0xf4, 0xfb, 0x34, 0x46, 0xa8, 0x4b, 0x35, 0x10, 0x2, 0x19, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xf, 0x20, 0x14, 0x28, 0x3c, 0x4, 0x4];

        match Heartbeat::deserialize(&data) {
            Err(err) => assert!(false, err.description().to_string()),
            Ok(have) => assert_eq!(have, want)
        }
    }
    //ToDo Serialization with Signature
}