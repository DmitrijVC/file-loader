#[macro_use] extern crate magic_crypt;
#[macro_use] extern crate strenc;
strenc_initialize!();

use std::path::Path;
use std::{io, fmt};
use std::io::{Read, Write,     Error, ErrorKind};
use std::fmt::{Display, Formatter};
use magic_crypt::{MagicCrypt256, MagicCryptTrait};
use std::string::FromUtf8Error;
pub use strenc::{enc};
pub use file_loader_procedural::f_load;


/// Macro which should be used in the main .rs file just above the other crates uses.
///
/// **Other macros won't work without the initialization.**
///
/// # Examples
///
/// ```
/// #[macro_use] extern crate file_loader as fl;
/// file_loader_initialize!();
///
/// use fl::InnerFile;
/// ```
#[macro_export]
macro_rules! file_loader_initialize {
    () => {
        use file_loader::internal_strenc;
    };
}

/// Macro that helps with creatring new instance of an InnerFile struct.
///
/// # Arguments
///
/// * `file_name` - Path to the file which should be loaded.
///
/// # Examples
///
/// ```
/// let inner_file = file_loader_new!("Cargo.toml");
/// ```
#[macro_export]
macro_rules! file_loader_new {
    ( $p:literal ) => {
        {
            file_loader::InnerFile::new_from_fload(file_loader::f_load!($p))
        }
    };
}

/// Struct that helps to operate on an encrypted file content inside the memory.
#[derive(Clone)]
pub struct InnerFile {
    crypt: MagicCrypt256,
    content: String,
    key: String,
}

impl InnerFile {
    /// Returns instance of an InnerFile struct.
    ///
    /// # Arguments
    ///
    /// * `result` - Result from the `f_load` macro.
    ///
    /// # Examples
    ///
    /// ```
    /// #[macro_use] extern crate file_loader as fl;
    /// file_loader_initialize!();
    ///
    /// let inner_file = fl::InnerFile::new_from_fload(f_load!("Cargo.toml"));
    /// ```
    pub fn new_from_fload(result: String) -> Self {
        let x: Vec<&str> = result.split("\\u{0}").peekable().collect();

        let key = x.get(0).unwrap().to_string();
        let content = x.get(1).unwrap().to_string();

        Self {
            crypt: new_magic_crypt!(&key, 256),
            content,
            key,
        }
    }

    /// Saves the InnerFile into the drive.
    ///
    /// # Arguments
    ///
    /// * `path` - Path where the file should be saved to.
    pub fn save_to<P>(&self, path: P) -> io::Result<()>
        where P: AsRef<Path> {
        std::fs::write(path, self.crypt.decrypt_base64_to_bytes(&self.content).unwrap())
    }

    /// Checks if the file is properly encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.crypt.decrypt_base64_to_bytes(&self.content).is_ok()
    }

    /// Clones the InnerFile's key.
    pub fn get_key(&self) -> String {
        self.key.clone()
    }

    /// Clones the encrypted content of the InnerFile
    pub fn get_content_encrypted(&self) -> String {
        self.content.clone()
    }

    /// Borrows the encrypted content of the InnerFile
    pub fn get_content_encrypted_borrow(&self) -> &String {
        &self.content
    }

    /// Returns the decrypted content of the InnerFile
    pub fn get_content(&self) -> Vec<u8> {
        match self.crypt.decrypt_base64_to_bytes(&self.content) {
            Ok(content) => content,
            Err(_) => {
                self.content.clone().into_bytes()
            }
        }
    }

    /// Tries to convert decrypted content to the String
    pub fn get_content_to_string(&self) -> Result<String, FromUtf8Error> {
        String::from_utf8(self.get_content())
    }

    /// Converts decrypted content to the String, even if there are invalid UTF-8 sequences
    pub fn get_content_to_string_forced(&self) -> String {
        format!("{}", String::from_utf8_lossy(self.get_content().as_slice()))
    }

    /// Replaces the decrypted content of the InnerFile
    ///
    /// # Arguments
    ///
    /// * `bytes` - New content.
    pub fn replace_content(&mut self, bytes: &[u8]) {
        self.content = self.crypt.encrypt_bytes_to_base64(bytes);
    }
}

impl Read for InnerFile {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        buf.write(&self.get_content())
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
            self.get_content_to_string_forced()
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
