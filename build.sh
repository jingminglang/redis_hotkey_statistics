#!/bin/bash

godep save
go build main.go
mv main build/
