#[macro_use] extern crate magic_crypt;
#[macro_use] extern crate file_loader_procedural;
#[macro_use] extern crate strenc;

use std::path::Path;
use magic_crypt::{MagicCrypt256, MagicCryptTrait, MagicCryptError};
use std::{io, fmt};
use std::io::{BufRead, Read, Write, Take, Bytes, Chain, IoSliceMut, Error, ErrorKind};
use std::fmt::{Display, Formatter};
use std::borrow::Cow;
use std::os::windows::fs::FileExt;
use std::os::windows::io::IntoRawHandle;
use std::ffi::c_void;


#[macro_export]
macro_rules! f_create {
    ( $p:expr, $k:expr ) => {
        {
            file_loader::InnerFile::new($k.to_string(), f_load!($p, $k).to_string())
        }
    };
}

#[derive(Clone)]
pub struct InnerFile {
    crypt: MagicCrypt256,
    content: String,
    key: String,
}

impl InnerFile {
    pub fn new(key: String, content: String) -> Self {
        Self {
            crypt: new_magic_crypt!(&key, 256),
            content,
            key,
        }
    }

    pub fn save_to<P>(&self, path: P) -> io::Result<()>
        where P: AsRef<Path> {
        std::fs::write(path, self.crypt.decrypt_base64_to_bytes(&self.content).unwrap())
    }

    pub fn is_encrypted(&self) -> bool {
        self.crypt.decrypt_base64_to_bytes(&self.content).is_ok()
    }

    pub fn is_encoded(&self) -> bool {
        base64::decode(&self.content).is_ok()
    }

    pub fn get_content_encrypted(&self) -> String {
        self.content.clone()
    }

    pub fn get_content_encrypted_borrow(&self) -> &String {
        &self.content
    }

    pub fn get_content(&self) -> Vec<u8> {
        match self.crypt.decrypt_base64_to_bytes(&self.content) {
            Ok(content) => content,
            Err(_) => {
                if let Ok(content) = base64::decode(&self.content) {
                    content
                } else {
                    self.content.clone().into_bytes()
                }
            }
        }
    }

    /*pub fn get_content_bytes(&self) -> &[u8] {
        let result = self.crypt.decrypt_base64_to_bytes(&self.content);
        match result {
            Ok(_) => result.unwrap().as_slice(),
            Err(_) => {
                if let Ok(content) = base64::decode(&self.content) {
                    content.as_slice()
                } else {
                    self.content.as_bytes()
                }
            }
        }
    }*/

    pub fn replace_content(&mut self, bytes: &[u8]) {
        self.content = self.crypt.encrypt_bytes_to_base64(bytes);
    }
}

impl Read for InnerFile {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        buf.write(&self.get_content())  // b
    }

    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        let string = if let Ok(string) = String::from_utf8(self.get_content()) {
            string
        } else {
            return Err(Error::new(ErrorKind::InvalidData, "stream did not contain valid UTF-8"));
        };

        buf.push_str(&*string);
        Ok(string.len())
    }
}

impl Display for InnerFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.get_content().len()    // b
        )
    }
}

impl Write for InnerFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut content = self.get_content();

        let size = if let Ok(size) = content.write(buf) {
            self.replace_content(&content);
            size
        } else {
            0
        };

        Ok(size)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
