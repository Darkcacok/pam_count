# Описание
Это PAM модуль для операционной системы astra linux.

Если пользователь вводит неверный пароль, то в faillog
счетчик входа увеличивается на единицу. Как только польователь
три раза подряд вводит неверный пароль, вход в ОС ему блокируется.
Вход разблокируется, если в систему зайдет пользователь
с правами администратора. Вход разблокируется последнему
пользователю который был заблокирован.

Для пользователей с правами администратора подсчет не ведется.

Для использования в других GNU/Linux нужно переписать функцию
определения является ли пользователь администратором(имееются ли у него права админа).

# Компиляция
<sudo gcc -fPIC -fno-stack-protector -c pam_count.c>
<sudo ld -x --shared -o /lib/security/pam_count.so pam_count.o>

# Дополнительные действия
В файл vim /etc/pam.d/common-auth добавить вначале:
**auth requisite  pam_count.so**

В файл vim /etc/pam.d/common-account добавить вначале:
**account requisite pam_count.so**

# Просмотр файла faillog
<faillog -a>
