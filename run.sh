#!/bin/bash
mvn package
echo -n "" > publickeys.conf
rm -rf privatekey*.conf
java -jar target/MChat-1.0-SNAPSHOT.jar alice 224.4.4.4 9000 & java -jar target/MChat-1.0-SNAPSHOT.jar bob 224.4.4.4 9000 & java -jar target/MChat-1.0-SNAPSHOT.jar trudy 224.4.4.4 9000
