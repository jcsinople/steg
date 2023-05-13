# Steg

Steg is a command-line application written in Rust that uses steganography techniques to hide a message within a collection of files.

## Features

1. **Hiding a message:** You can hide a secret message within a directory full of files. The message is encrypted using AES-256 in CBC mode with a password you provide, and then hidden in the files.

2. **Extracting a message:** You can also extract a hidden message from a directory of files. You'll need the same password that was used to hide the message. If the password is incorrect, you'll be notified.

## How to Run

To run the application, you'll first need to have Rust installed on your machine. If you don't have Rust installed, you can download it from the [official website](https://www.rust-lang.org/tools/install).

Once you have Rust installed, you can clone the repository and navigate to the directory:

```bash
git clone https://github.com/username/steg.git
cd steg
```

Then, you can build and run the application using Cargo (Rust's package manager):

```bash
cargo build --release
cargo run --release -- [COMMAND] [OPTIONS]
```

Replace [COMMAND] with hide to hide a message, or extract to extract a message. Replace [OPTIONS] with the appropriate options for the command you're running.

## Hiding a message
To hide a message, you'll need to provide the directory of files, the message to hide, and optionally, the number of bytes to hide per file:

```bash
cargo run --release -- hide --dir /path/to/files --message "Secret message" --bytes_per_file 1
```

You'll be prompted to enter a password. This password will be used to encrypt the message.

## Extracting a message

To extract a message, you'll need to provide the directory of files, and optionally, the number of files used to hide the information and the number of hidden bytes per file:

```bash
cargo run --release -- extract --dir /path/to/files --num_files 10 --bytes_per_file 1
```

You'll be prompted to enter a password. You'll need to enter the same password that was used to hide the message.

## License

This program is licensed under the [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/).

