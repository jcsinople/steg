// Import the necessary libraries
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::error::Error;
use std::path::PathBuf;
use structopt::StructOpt;
use aes_soft::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;
use rpassword::prompt_password_stdout;
use hex::encode;
use hex::decode;

// Define the AES256-CBC encryption block mode type
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Define the salt for the password-based key derivation function
const SALT: &[u8] = b"\x12\x34\x56\x78\x9A\xBC\xDE\xF0\x12\x34\x56\x78\x9A\xBC\xDE\xF0";

// Define the fill character used to complete missing bytes
const FILL_CHARACTER: u8 = 0; // Caracter de relleno para completar bytes faltantes

// Define the Command enum with Hide and Extract variants
#[derive(StructOpt, Debug)]
#[structopt(name = "steg")]
enum Command {
    Hide {
        // Directory that contains the files in which to hide the message
        #[structopt(parse(from_os_str))]
        dir: PathBuf,

        // Message to hide in the files
        message: String,

        // Number of bytes to hide in each file
        #[structopt(long, default_value = "1")]
        bytes_per_file: usize,
    },
    Extract {
        // Directory that contains the files with the hidden message
        #[structopt(parse(from_os_str))]
        dir: PathBuf,

        // Number of files used to hide the information
        #[structopt(long)]
        num_files: Option<usize>,

        // Number of hidden bytes in each file
        #[structopt(long, default_value = "1")]
        bytes_per_file: usize,
    },
}

// Main function
fn main() -> Result<(), Box<dyn Error>> {
    // Parse the command line arguments
    let command = Command::from_args();

    // Prompt for password
    let password = prompt_password_stdout("Password: ")?;

    // Create an AES256 key
    let mut key = [0; 32]; // Aes256 key size

    // Derive the key from the password
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), SALT, 10_000, &mut key);

    // Execute the command
    match command {
        Command::Hide {
            dir,
            message,
            bytes_per_file,
        } => {
            // Create the cipher
            let cipher = Aes256Cbc::new_var(&key, SALT).unwrap();

            // Encrypt the message
            let ciphertext = cipher.encrypt_vec(message.as_bytes());

            // Hide the message
            hide_message(&dir, encode(&ciphertext), bytes_per_file)?;
        }
        Command::Extract {
            dir,
            num_files,
            bytes_per_file,
        } => {
            // Extract the hidden message
            let hidden_message = extract_hidden_message(&dir, num_files, bytes_per_file)?;

            // Remove null characters from the hidden message
            let hidden_message_without_nulls: String = hidden_message.chars().filter(|&c| c != '\0').collect();    

            // Create the cipher        
            let cipher = Aes256Cbc::new_var(&key, SALT).unwrap();

            // Decode the hidden message from hex to bytes
            let ciphertext = match decode(&hidden_message_without_nulls){
                Ok(ct) => ct,
                Err(_) => {
                    return Err(From::from("The provided password is incorrect."));
                }
            };

            // Decrypt the hidden message
            let decrypted_ciphertext = match cipher.decrypt_vec(&ciphertext){
                Ok(dc) => dc,
                Err(_) => {
                    return Err(From::from("The provided password is incorrect."));
                }
            };

            // Print the hidden message
            println!("Hidden message: {}", String::from_utf8(decrypted_ciphertext).unwrap());
            
        }
    }

    Ok(())
}

// Function to hide the message in the files of the directory
fn hide_message(directory: &PathBuf, message: String, bytes_per_file: usize) -> Result<(), Box<dyn Error>> {
    // Convert the message into a byte sequence
    let mut message_bytes = message.into_bytes();

    // Calculate the amount of files needed to hide all the bytes of the message
    let num_files = (message_bytes.len() + bytes_per_file - 1) / bytes_per_file;

    // Variable to store the amount of files used
    let mut num_files_used = 0; 

    // Hide the bytes of the message in the files
    for (_index, file_path) in get_files_in_directory(directory)?.into_iter().enumerate() {
        // If all bytes have already been hidden or the necessary amount of files has been used, break out of the loop
        if message_bytes.is_empty() || num_files_used >= num_files {
            break;
        }

        // Open the file in append mode and write the bytes at the end
        let mut file = OpenOptions::new().append(true).open(file_path)?;

        for _ in 0..bytes_per_file {
            if let Some(byte_to_append) = message_bytes.pop() {
                file.write_all(&[byte_to_append])?;
            } else {
                // Write the fill character
                file.write_all(&[FILL_CHARACTER])?;
            }
        }

        // Increment the amount of files used
        num_files_used += 1;
    }

    // Display the amount of files used
    println!("{} file(s) were used to hide the message.", num_files_used);

    // Muestra una advertencia si no hay suficientes archivos para ocultar todo el mensaje
    if !message_bytes.is_empty() {
        eprintln!("Warning: There are not enough files to hide the entire message.");
    }

    Ok(())
}

// Function to extract the hidden message from the files in the directory. Takes the directory, the amount of files used to hide the information, and the amount of hidden bytes in each file. Extracts the hidden message by reading the last hidden bytes of the files.
fn extract_hidden_message(directory: &PathBuf, num_files: Option<usize>, bytes_per_file: usize) -> Result<String, Box<dyn Error>> {
    // Get the list of files in the directory
    let files = get_files_in_directory(directory)?;

    // Calculate the amount of files to use
    let num_files_to_use = num_files.unwrap_or(files.len());

    // Vector to store the bytes of the hidden message
    let mut hidden_message_bytes = Vec::new();

    // Read the last bytes_per_file bytes of each file and add them to the vector
    for (index, file_path) in files.into_iter().enumerate() {
        // If the number of files to use is reached, break out of the loop
        if index >= num_files_to_use {
            break;
        }

        // Open the file in read mode
        let mut file = fs::File::open(file_path)?;

        // Create a buffer to store the file content
        let mut buffer = Vec::new();

        // Read the file content into the buffer
        file.read_to_end(&mut buffer)?;

        // Extract the last bytes_per_file bytes from the buffer and add them to the hidden_message_bytes vector
        for i in buffer.len().saturating_sub(bytes_per_file)..buffer.len() {
            hidden_message_bytes.push(buffer[i]);
        }
    }

    // Reverse the vector of bytes to restore the original order
    hidden_message_bytes.reverse();

    // Convert the vector of bytes into a string and return it
    Ok(String::from_utf8_lossy(&hidden_message_bytes).to_string())
}

// Function to get the list of files in a directory. Takes the directory and returns a vector of file paths.
fn get_files_in_directory(directory: &PathBuf) -> Result<Vec<PathBuf>, Box<dyn Error>> {

    // Create a new vector to store the file paths
    let mut files = Vec::new();

   // Iterate over the directory entries
    for entry in fs::read_dir(directory)? {
        // Get the information of the current entry
        let entry = entry?;

        // Check if the input is a file
        if entry.path().is_file() {
            // If it's a file, add its path to the file array
            files.push(entry.path());
        }
    }

    // Sort the file paths
    files.sort();

    // Return the vector of file paths
    Ok(files)
}
