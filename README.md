# explicit_ec_params
How to identify explicit ec parameters in a Certificate and flag it

#How to compile and execute
usecase1:
gcc -o <final executable file>  <.c file you want to compile> -I/root/openssl-static/include/ -L/root/openssl-static/lib/ -Wl,--whole-archive -lssl -Wl,--no-whole-archive -lcrypto -ldl -lpthread -lz -lm
usecase2:
gcc check_ec_cert.c -o check_ec_cert -lssl -lcrypto

#How to run the program
./check_ec_cert explicit_ec_cert.pem
./check_ec_cert_f5_3 test/certs/my_server_ecc.crt test/rootCA_ecc.crt
