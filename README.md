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
