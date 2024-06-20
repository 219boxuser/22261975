Прошу прощения за путаницу. Давайте рассмотрим более подробное руководство по выполнению всех трех модулей, включая правильный расчет IP-адресации, а также корректные инструкции по настройке сетевых интерфейсов. Уточним также адресацию для ISP.

### Подробное руководство по выполнению всех трех модулей

#### Основные настройки VirtualBox

1. **Создание виртуальных машин (ВМ)**
   - **HQ-R**: роутер в центральном офисе
   - **HQ-SRV**: сервер в центральном офисе
   - **BR-R**: роутер в филиале
   - **BR-SRV**: сервер в филиале
   - **CLI**: клиентская машина
   - **ISP**: интернет-провайдер

2. **Сетевые адаптеры**
   - Все машины должны иметь два сетевых адаптера:
     - **Adapter 1**: `NAT` для выхода в интернет.
     - **Adapter 2**: `Host-only Adapter` для внутренней сети.

3. **Основные параметры машин**
   - **Операционная система**: Ubuntu 24.04.
   - **RAM**: 2048 MB (минимум).
   - **Процессоры**: 2 CPU.

### Модуль 1: Выполнение работ по проектированию сетевой инфраструктуры

#### Задание 1: Базовая настройка устройств

1. **Присвоение имен устройствам**
   - Выполните вход в каждую ВМ и задайте имя с помощью команды:
     ```bash
     sudo hostnamectl set-hostname <имя_устройства>
     sudo reboot
     ```
   - Присвойте следующие имена:
     - HQ-R
     - HQ-SRV
     - BR-R
     - BR-SRV
     - CLI
     - ISP

2. **Расчет IP-адресации IPv4 и IPv6**
   - Определите адресацию для каждой сети:
     - **HQ** (центральный офис): сеть с пулом до 64 адресов (192.168.1.0/26).
     - **BRANCH** (филиал): сеть с пулом до 16 адресов (192.168.2.0/28).
     - **ISP** (провайдер): сеть для связи между HQ-R и ISP (10.0.0.0/30).

   - Пример конфигурации для HQ:
     - HQ-R: 192.168.1.1/26
     - HQ-SRV: 192.168.1.2/26
     - CLI: 192.168.1.3/26

   - Пример конфигурации для BRANCH:
     - BR-R: 192.168.2.1/28
     - BR-SRV: 192.168.2.2/28

   - Пример конфигурации для ISP:
     - ISP: 10.0.0.1/30
     - HQ-R (интерфейс, подключенный к ISP): 10.0.0.2/30

3. **Применение конфигурации на каждом устройстве**
   - Например, для HQ-R:
     ```bash
     sudo ip addr add 192.168.1.1/26 dev eth0
     sudo ip addr add 10.0.0.2/30 dev eth1
     sudo ip link set eth0 up
     sudo ip link set eth1 up
     ```

   - Для ISP:
     ```bash
     sudo ip addr add 10.0.0.1/30 dev eth0
     sudo ip link set eth0 up
     ```

#### Задание 2: Настройка внутренней динамической маршрутизации

1. **Установка FRR на роутерах**
   - На HQ-R и BR-R:
     ```bash
     sudo apt-get update
     sudo apt-get install frr frr-doc
     ```

2. **Выбор протокола динамической маршрутизации**
   - Пример настройки OSPF на HQ-R:
     ```bash
     sudo vtysh
     configure terminal
     router ospf
     network 192.168.1.0/26 area 0
     network 192.168.2.0/28 area 0
     network 10.0.0.0/30 area 0
     exit
     write memory
     exit
     ```

#### Задание 3: Настройка DHCP на роутере HQ-R

1. **Установка DHCP-сервера**
   ```bash
   sudo apt-get install isc-dhcp-server
   ```

2. **Конфигурация DHCP**
   - Редактирование файла `/etc/dhcp/dhcpd.conf`:
     ```conf
     subnet 192.168.1.0 netmask 255.255.255.192 {
         range 192.168.1.10 192.168.1.50;
         option routers 192.168.1.1;
         option domain-name-servers 192.168.1.2;
     }
     host hq-srv {
         hardware ethernet <MAC_ADDRESS>;
         fixed-address 192.168.1.2;
     }
     ```
   - Запуск DHCP сервера:
     ```bash
     sudo systemctl restart isc-dhcp-server
     sudo systemctl enable isc-dhcp-server
     ```

#### Задание 4: Настройка локальных учетных записей

1. **Добавление пользователей на каждом устройстве**
   - Команды для создания пользователя и задания пароля:
     ```bash
     sudo useradd -m -s /bin/bash admin
     echo 'admin:P@ssw0rd' | sudo chpasswd
     sudo useradd -m -s /bin/bash branch_admin
     echo 'branch_admin:P@ssw0rd' | sudo chpasswd
     sudo useradd -m -s /bin/bash network_admin
     echo 'network_admin:P@ssw0rd' | sudo chpasswd
     ```

#### Задание 5: Измерение пропускной способности

1. **Установка iperf**
   ```bash
   sudo apt-get install iperf3
   ```

2. **Измерение пропускной способности**
   - На HQ-R:
     ```bash
     iperf3 -s
     ```
   - На ISP:
     ```bash
     iperf3 -c 10.0.0.2
     ```

#### Задание 6: Создание скриптов для резервного копирования

1. **Создание скриптов**
   - Пример скрипта для HQ-R:
     ```bash
     #!/bin/bash
     sudo vtysh -c 'write file'
     tar -czf /backup/hq-r-config.tar.gz /etc/frr/
     ```

2. **Запуск скриптов**
   ```bash
   sudo bash /path/to/backup_script.sh
   ```

#### Задание 7: Настройка SSH на порту 2222

1. **Редактирование конфигурации SSH**
   - Измените файл `/etc/ssh/sshd_config`:
     ```conf
     Port 2222
     ```

2. **Перенаправление трафика**
   - На роутере HQ-R:
     ```bash
     sudo iptables -t nat -A PREROUTING -p tcp --dport 2222 -j DNAT --to-destination 192.168.1.2:2222
     sudo iptables -A FORWARD -p tcp --dport 2222 -d 192.168.1.2 -j ACCEPT
     ```

#### Задание 8: Контроль доступа по SSH

1. **Настройка на всех устройствах кроме CLI**
   - Редактирование файла `/etc/ssh/sshd_config`:
     ```conf
     AllowUsers admin branch_admin network_admin
     ```

### Модуль 2: Организация сетевого администрирования

#### Задание 1: Настройка DNS-сервера

1. **Установка BIND9**
   ```bash
   sudo apt-get install bind9 bind9utils bind9-doc
   ```

2. **Конфигурация DNS**
   - Создание директории для зон:
     ```bash
     sudo mkdir -p /etc/bind/zones
     ```

   - Создание файла зоны прямого просмотра:
     ```bash
     sudo nano /etc/bind/zones/db.hq.work
     ```
     Содержимое файла:
     ```conf
     $TTL    604800
     @       IN      SOA     ns.hq.work. admin.hq.work. (
                               2         ; Serial
                          604800         ; Refresh
                           86400         ; Retry
                         2419200         ; Expire
                          604800 )       ; Negative Cache TTL
     ;
     @       IN      NS      ns.hq.work.
     ns      IN      A       192.168.1.2
     hq-r    IN      A       192.168.1.1
     hq-srv  IN      A       192.168.1.2
     ```

   - Создание файла зоны обратного просмотра:
     ```bash
     sudo nano /etc

/bind/zones/db.192.168.1
     ```
     Содержимое файла:
     ```conf
     $TTL    604800
     @       IN      SOA     ns.hq.work. admin.hq.work. (
                               2         ; Serial
                          604800         ; Refresh
                           86400         ; Retry
                         2419200         ; Expire
                          604800 )       ; Negative Cache TTL
     ;
     @       IN      NS      ns.
     1       IN      PTR     hq-r.hq.work.
     2       IN      PTR     hq-srv.hq.work.
     ```

   - Редактирование главного конфигурационного файла:
     ```bash
     sudo nano /etc/bind/named.conf.local
     ```
     Добавление зон:
     ```conf
     zone "hq.work" {
         type master;
         file "/etc/bind/zones/db.hq.work";
     };

     zone "1.168.192.in-addr.arpa" {
         type master;
         file "/etc/bind/zones/db.192.168.1";
     };
     ```

   - Перезапуск BIND9:
     ```bash
     sudo systemctl restart bind9
     ```

#### Задание 2: Синхронизация времени

1. **Установка NTP**
   ```bash
   sudo apt-get install ntp
   ```

2. **Конфигурация NTP на HQ-R**
   - Редактирование файла `/etc/ntp.conf`:
     ```conf
     server 127.127.1.0     # local clock
     fudge 127.127.1.0 stratum 5

     # Allow LAN machines to synchronize with this ntp server
     restrict 192.168.1.0 mask 255.255.255.192 nomodify notrap
     ```

   - Перезапуск службы NTP:
     ```bash
     sudo systemctl restart ntp
     sudo systemctl enable ntp
     ```

#### Задание 3: Настройка домена

1. **Установка и настройка Samba для домена**
   ```bash
   sudo apt-get install samba
   ```

2. **Конфигурация домена в файле `/etc/samba/smb.conf`**
   ```conf
   [global]
   workgroup = HQ
   security = user
   passdb backend = tdbsam

   [hq-srv]
   path = /srv/samba/hq-srv
   read only = no
   ```

3. **Создание необходимых директорий и пользователей**
   ```bash
   sudo mkdir -p /srv/samba/hq-srv
   sudo chown -R nobody:nogroup /srv/samba/hq-srv
   sudo smbpasswd -a admin
   sudo smbpasswd -a branch_admin
   sudo smbpasswd -a network_admin
   ```

   - Перезапуск Samba:
     ```bash
     sudo systemctl restart smbd
     ```

#### Задание 4: Реализация файлового сервера

1. **Настройка SMB-сервера**
   - Добавление общих папок в файл `/etc/samba/smb.conf`:
     ```conf
     [Branch_Files]
     path = /srv/samba/Branch_Files
     valid users = branch_admin
     read only = no

     [Network]
     path = /srv/samba/Network
     valid users = network_admin
     read only = no

     [Admin_Files]
     path = /srv/samba/Admin_Files
     valid users = admin
     read only = no
     ```

2. **Создание директорий**
   ```bash
   sudo mkdir -p /srv/samba/Branch_Files
   sudo mkdir -p /srv/samba/Network
   sudo mkdir -p /srv/samba/Admin_Files
   sudo chown -R nobody:nogroup /srv/samba/Branch_Files
   sudo chown -R nobody:nogroup /srv/samba/Network
   sudo chown -R nobody:nogroup /srv/samba/Admin_Files
   ```

### Модуль 3: Эксплуатация объектов сетевой инфраструктуры

#### Задание 1: Настройка мониторинга с использованием rsyslog

1. **Установка rsyslog**
   - На каждой машине (HQ-R, HQ-SRV, BR-R, BR-SRV, CLI, ISP):
     ```bash
     sudo apt-get update
     sudo apt-get install rsyslog
     ```

2. **Конфигурация rsyslog**
   - На HQ-SRV откройте файл конфигурации rsyslog:
     ```bash
     sudo nano /etc/rsyslog.conf
     ```
   - Добавьте следующие строки для приема логов с других хостов:
     ```conf
     module(load="imudp")
     input(type="imudp" port="514")

     module(load="imtcp")
     input(type="imtcp" port="514")
     ```

   - Перезапустите службу rsyslog:
     ```bash
     sudo systemctl restart rsyslog
     ```

   - На других машинах (HQ-R, BR-R, BR-SRV, CLI, ISP) откройте файл конфигурации rsyslog:
     ```bash
     sudo nano /etc/rsyslog.conf
     ```
   - Добавьте строку для отправки логов на HQ-SRV:
     ```conf
     *.* @192.168.1.2:514
     ```

   - Перезапустите службу rsyslog на всех машинах:
     ```bash
     sudo systemctl restart rsyslog
     ```

3. **Проверка работы мониторинга**
   - На HQ-SRV проверьте файлы логов:
     ```bash
     sudo tail -f /var/log/syslog
     ```

#### Задание 2: Настройка центра сертификации на базе HQ-SRV

1. **Установка OpenSSL**
   - На HQ-SRV:
     ```bash
     sudo apt-get install openssl
     ```

2. **Создание собственного центра сертификации (CA)**
   - Создайте директории и файлы для CA:
     ```bash
     sudo mkdir /etc/ssl/myCA
     cd /etc/ssl/myCA
     sudo touch index.txt
     sudo echo 1000 > serial
     ```

   - Создайте конфигурационный файл OpenSSL:
     ```bash
     sudo nano /etc/ssl/myCA/openssl.cnf
     ```
     Содержимое файла:
     ```conf
     [ ca ]
     default_ca = CA_default

     [ CA_default ]
     dir = /etc/ssl/myCA
     database = $dir/index.txt
     new_certs_dir = $dir/newcerts
     certificate = $dir/cacert.pem
     serial = $dir/serial
     private_key = $dir/private/cakey.pem
     default_md = sha256
     policy = policy_loose
     default_days = 365
     default_crl_days = 30

     [ policy_loose ]
     countryName = optional
     stateOrProvinceName = optional
     organizationName = optional
     organizationalUnitName = optional
     commonName = supplied
     emailAddress = optional

     [ req ]
     distinguished_name = req_distinguished_name
     x509_extensions = v3_ca

     [ req_distinguished_name ]
     commonName = Common Name (e.g. server FQDN or YOUR name)
     commonName_max = 64

     [ v3_ca ]
     subjectKeyIdentifier = hash
     authorityKeyIdentifier = keyid:always,issuer
     basicConstraints = critical, CA:true
     ```

   - Генерация приватного ключа и самоподписанного сертификата для CA:
     ```bash
     sudo openssl genpkey -algorithm RSA -out /etc/ssl/myCA/private/cakey.pem
     sudo openssl req -x509 -new -nodes -key /etc/ssl/myCA/private/cakey.pem -sha256 -days 3650 -out /etc/ssl/myCA/cacert.pem -config /etc/ssl/myCA/openssl.cnf
     ```

3. **Выдача сертификатов для SSH и веб-серверов**
   - Создание запроса на сертификат (CSR) для SSH-сервера:
     ```bash
     sudo openssl req -new -nodes -newkey rsa:2048 -keyout /etc/ssl/myCA/private/sshserver.key -out /etc/ssl/myCA/sshserver.csr
     ```

   - Подписание CSR центром сертификации:
     ```bash
     sudo openssl ca -config /etc/ssl/myCA/openssl.cnf -in /etc/ssl/myCA/sshserver.csr -out /etc/ssl/myCA/sshserver.crt -batch
     ```

   - Установка сертификатов на SSH-сервер (HQ-SRV):
     ```bash
     sudo cp /etc/ssl/myCA/sshserver.crt /etc/ssh/ssh_host_rsa_key-cert.pub
     sudo cp /etc/ssl/myCA/private/sshserver.key /etc/ssh/ssh_host_rsa_key
     sudo systemctl restart ssh
     ```

   - Аналогично создайте и установите сертификаты для веб-сервера.

#### Задание 

3: Настройка SSH

1. **Изменение конфигурации SSH на всех Linux-хостах (HQ-SRV, BR-SRV, CLI, ISP)**
   - Редактирование файла `/etc/ssh/sshd_config`:
     ```bash
     sudo nano /etc/ssh/sshd_config
     ```

   - Внесите следующие изменения:
     ```conf
     Port 2222
     PermitRootLogin no
     PasswordAuthentication no
     ChallengeResponseAuthentication no
     UsePAM yes
     AllowUsers admin branch_admin network_admin
     MaxAuthTries 4
     LoginGraceTime 60
     ```

   - Создайте файл баннера:
     ```bash
     sudo nano /etc/ssh/banner
     ```
     Содержимое файла:
     ```
     Authorized access only!
     ```

   - Добавьте следующую строку в конфигурацию SSH:
     ```conf
     Banner /etc/ssh/banner
     ```

   - Перезапустите службу SSH:
     ```bash
     sudo systemctl restart ssh
     ```

2. **Настройка SSH на нестандартный порт и ограничение попыток входа**
   - Все настройки были выполнены в предыдущем шаге.

#### Задание 4: Антивирусная защита с использованием ClamAV

1. **Установка ClamAV**
   - На HQ-SRV и BR-SRV:
     ```bash
     sudo apt-get install clamav clamav-daemon
     ```

2. **Настройка ежедневного сканирования**
   - Создайте файл скрипта для сканирования:
     ```bash
     sudo nano /usr/local/bin/daily_scan.sh
     ```
     Содержимое файла:
     ```bash
     #!/bin/bash
     clamscan -r / --log=/var/log/clamav/daily_scan.log
     ```

   - Сделайте скрипт исполняемым:
     ```bash
     sudo chmod +x /usr/local/bin/daily_scan.sh
     ```

   - Настройте cron для ежедневного запуска сканирования:
     ```bash
     sudo crontab -e
     ```
     Добавьте строку:
     ```
     0 2 * * * /usr/local/bin/daily_scan.sh
     ```

#### Задание 5: Настройка системы управления трафиком на роутере BR-R

1. **Настройка iptables на BR-R для управления входящим трафиком**
   - Разрешите необходимые порты:
     ```bash
     sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
     sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
     sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
     sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
     sudo iptables -A INPUT -p icmp -j ACCEPT
     ```

   - Запретите все остальные подключения:
     ```bash
     sudo iptables -A INPUT -j DROP
     ```

   - Сохраните правила iptables:
     ```bash
     sudo apt-get install iptables-persistent
     sudo netfilter-persistent save
     sudo netfilter-persistent reload
     ```

#### Задание 6: Настройка виртуального принтера с CUPS на BR-SRV

1. **Установка CUPS**
   ```bash
   sudo apt-get install cups
   ```

2. **Добавление пользователя в группу lpadmin**
   ```bash
   sudo usermod -aG lpadmin $(whoami)
   ```

3. **Конфигурация CUPS для доступа**
   - Редактирование файла `/etc/cups/cupsd.conf`:
     ```bash
     sudo nano /etc/cups/cupsd.conf
     ```

   - Разрешите доступ:
     ```conf
     <Location />
       Order allow,deny
       Allow all
     </Location>

     <Location /admin>
       Order allow,deny
       Allow all
     </Location>

     <Location /admin/conf>
       Order allow,deny
       Allow all
     </Location>
     ```

   - Перезапуск службы CUPS:
     ```bash
     sudo systemctl restart cups
     ```

4. **Добавление принтера через веб-интерфейс CUPS**
   - Откройте веб-браузер и перейдите по адресу `http://<BR-SRV_IP>:631`
   - Перейдите в раздел `Administration` и добавьте принтер, следуя инструкциям на экране.

#### Задание 7: Установка защищенного туннеля между офисами

1. **Установка и настройка OpenVPN на HQ-R и BR-R**
   - Установка OpenVPN:
     ```bash
     sudo apt-get install openvpn easy-rsa
     ```

2. **Настройка CA и генерация сертификатов**
   - На HQ-R выполните следующие команды:
     ```bash
     make-cadir ~/openvpn-ca
     cd ~/openvpn-ca
     ```

   - Редактирование файла `vars`:
     ```bash
     sudo nano vars
     ```
     Измените следующие строки:
     ```bash
     export KEY_COUNTRY="US"
     export KEY_PROVINCE="CA"
     export KEY_CITY="SanFrancisco"
     export KEY_ORG="Fort-Funston"
     export KEY_EMAIL="me@myhost.mydomain"
     export KEY_OU="MyOrganizationalUnit"
     ```

   - Сгенерируйте CA:
     ```bash
     source vars
     ./clean-all
     ./build-ca
     ./build-key-server server
     ./build-dh
     openvpn --genkey --secret keys/ta.key
     ```

   - Скопируйте сертификаты на BR-R:
     ```bash
     scp -r ~/openvpn-ca/keys/ root@192.168.2.1:/etc/openvpn/
     ```

3. **Конфигурация серверов OpenVPN**
   - На HQ-R:
     ```bash
     sudo nano /etc/openvpn/server.conf
     ```
     Содержимое файла:
     ```conf
     port 1194
     proto udp
     dev tun
     ca /etc/openvpn/keys/ca.crt
     cert /etc/openvpn/keys/server.crt
     key /etc/openvpn/keys/server.key
     dh /etc/openvpn/keys/dh2048.pem
     tls-auth /etc/openvpn/keys/ta.key 0
     cipher AES-256-CBC
     user nobody
     group nogroup
     server 10.8.0.0 255.255.255.0
     persist-key
     persist-tun
     status /var/log/openvpn/status.log
     log-append /var/log/openvpn/openvpn.log
     verb 3
     ```

   - На BR-R аналогично создайте конфигурационный файл клиента:
     ```bash
     sudo nano /etc/openvpn/client.conf
     ```
     Содержимое файла:
     ```conf
     client
     dev tun
     proto udp
     remote 192.168.1.1 1194
     resolv-retry infinite
     nobind
     user nobody
     group nogroup
     persist-key
     persist-tun
     ca /etc/openvpn/keys/ca.crt
     cert /etc/openvpn/keys/client.crt
     key /etc/openvpn/keys/client.key
     tls-auth /etc/openvpn/keys/ta.key 1
     cipher AES-256-CBC
     verb 3
     ```

   - Запустите OpenVPN на обеих машинах:
     ```bash
     sudo systemctl start openvpn@server
     sudo systemctl enable openvpn@server
     ```

#### Задание 8: Настройка мониторинга параметров производительности

1. **Настройка мониторинга с использованием rsyslog**
   - Выполните настройки как указано в Задании 1.

2. **Конфигурация мониторинга параметров**
   - На всех машинах, где установлены rsyslog, добавьте следующие строки в файл конфигурации:
     ```bash
     sudo nano /etc/rsyslog.d/monitoring.conf
     ```
     Добавьте:
     ```conf
     local0.* /var/log/monitoring.log
     ```

   - На HQ-SRV настройте cron для мониторинга:
     ```bash
     sudo nano /usr/local/bin/monitoring.sh
     ```
     Содержимое файла:
     ```bash
     #!/bin/bash
     CPU_LOAD=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
     MEM_USED=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
     DISK_USED=$(df -h | grep '/$' | awk '{print $5}' | sed 's/%//g')

     if (( $(echo "$CPU_LOAD >= 70.0" |bc -l) )); then
         echo "Warning: High CPU load - $CPU_LOAD%" | logger -p local0.notice
     fi

     if (( $(echo "$MEM_USED >= 80.0" |bc -l) )); then
        

 echo "Warning: High Memory usage - $MEM_USED%" | logger -p local0.notice
     fi

     if (( $(echo "$DISK_USED >= 85.0" |bc -l) )); then
         echo "Warning: High Disk usage - $DISK_USED%" | logger -p local0.notice
     fi
     ```

   - Сделайте скрипт исполняемым и настройте cron:
     ```bash
     sudo chmod +x /usr/local/bin/monitoring.sh
     sudo crontab -e
     ```
     Добавьте строку:
     ```
     * * * * * /usr/local/bin/monitoring.sh
     ```

#### Задание 9: Настройка программного RAID 5 на BR-SRV

1. **Подключение и настройка дисков**
   - Убедитесь, что у вас есть три диска по 1 ГБ каждый (например, /dev/sdb, /dev/sdc, /dev/sdd).
   - Установка mdadm:
     ```bash
     sudo apt-get install mdadm
     ```

2. **Создание RAID 5**
   - Создание массива RAID 5:
     ```bash
     sudo mdadm --create --verbose /dev/md0 --level=5 --raid-devices=3 /dev/sdb /dev/sdc /dev/sdd
     ```

   - Создание файловой системы на RAID массиве:
     ```bash
     sudo mkfs.ext4 /dev/md0
     ```

   - Монтирование RAID массива:
     ```bash
     sudo mkdir -p /mnt/raid
     sudo mount /dev/md0 /mnt/raid
     ```

   - Добавление записи в /etc/fstab для автоматического монтирования:
     ```bash
     sudo nano /etc/fstab
     ```
     Добавьте строку:
     ```
     /dev/md0 /mnt/raid ext4 defaults 0 0
     ```

#### Задание 10: Настройка резервного копирования с Bacula

1. **Установка Bacula**
   - На HQ-SRV:
     ```bash
     sudo apt-get install bacula-server bacula-client
     ```

2. **Конфигурация Bacula Director**
   - Откройте конфигурационный файл:
     ```bash
     sudo nano /etc/bacula/bacula-dir.conf
     ```
   - Добавьте следующие строки для резервного копирования /etc на BR-SRV:
     ```conf
     Job {
       Name = "BackupBR-SRV"
       JobDefs = "DefaultJob"
       FileSet="Full Set"
       Schedule = "WeeklyCycle"
       Storage = File
       Messages = Standard
       Pool = Default
       Client = BR-SRV-fd
     }

     Client {
       Name = BR-SRV-fd
       Address = 192.168.2.2
       FDPort = 9102
       Catalog = MyCatalog
       Password = "brsrv_password"
       File Retention = 60 days
       Job Retention = 6 months
     }

     FileSet {
       Name = "Full Set"
       Include {
         Options {
           signature = MD5
         }
         File = /etc
       }
     }
     ```

3. **Конфигурация Bacula Client на BR-SRV**
   - Установка Bacula Client:
     ```bash
     sudo apt-get install bacula-client
     ```

   - Откройте конфигурационный файл:
     ```bash
     sudo nano /etc/bacula/bacula-fd.conf
     ```
   - Добавьте следующие строки:
     ```conf
     Director {
       Name = HQ-SRV-dir
       Password = "brsrv_password"
     }
     ```

   - Перезапустите службы Bacula:
     ```bash
     sudo systemctl restart bacula-fd
     sudo systemctl restart bacula-dir
     sudo systemctl restart bacula-sd
     ```

### Итог

Детальное выполнение всех шагов согласно этому руководству позволит вам успешно настроить и эксплуатировать сетевую инфраструктуру на базе Ubuntu 24.04.