#Компиляция
sudo gcc -fPIC -fno-stack-protector -c pam_count.c
sudo ld -x --shared -o /lib/security/pam_count.so pam_count.o
