# Steganography Tool for Image/File Hiding

## Overview
This tool allows you to hide text or files inside images using steganography (LSB method). It supports embedding and extracting messages via a simple GUI.

## Features
- Hide text inside PNG/BMP images
- Extract hidden messages from images
- Simple drag-and-drop GUI (Tkinter)
- Optional encryption for hidden messages

## Usage
1. Place your images in the `sample_images/` directory.
2. Install dependencies: `pip install -r requirements.txt`
3. Run the tool: `python main.py`

## Project Structure
- `main.py` - Entry point
- `steg.py` - Steganography logic
- `gui.py` - Tkinter GUI
 