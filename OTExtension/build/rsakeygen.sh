#!/bin/bash


for ((i = 0; i < $1; i++)); do
	openssl genrsa -out prvkey$i.pem 2048
	openssl rsa -in prvkey$i.pem -outform PEM -pubout -out pubkey$i.pem
done


