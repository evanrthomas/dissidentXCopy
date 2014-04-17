#!/bin/bash
python3 line_endings_encode.py genises.txt password "$1"
python3 universal_decode.py genises.txt password
