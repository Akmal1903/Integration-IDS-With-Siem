# Integration-IDS-With-Siem
Dokumentasi Teknis TA
1.	Install virtual machine seperti virtual box atau vmware
2.	Install dan siapkan 4 ubuntu pada virtual machine
3.	Install wazuh pada ubuntu, sebelum menginstall ubuntu pastikan 1 ubuntu untuk wazuh memenuhi system requirements wazuh
![image](https://github.com/user-attachments/assets/a088f75a-5de5-41cb-926c-f8abbfe71cee)
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
4.	Buka wazuh dashboard pada browser lalu login dengan username dan password yang diberikan saat proses instalasi selesai
5.	Install wazuh agent pada ketiga ubuntu lain nya, caranya tambahkan agent baru di wazuh dashboard lalu mengikuti istruksi yang diberikan
6.	Setelah agent terinstal pada masing-masing ketiga ubuntu tersebut, maka install Snort IDS pada ubuntu misal untuk snort IDS yang terinstall di salah satu ubuntu diberi nama agent1. 
    a.	sudo apt-get install snort -y
    b.	Pada agent1 buka /etc/snort/snort.conf dengan nano scroll down ke step 6, uncomment output alert_syslog: LOG_AUTH LOG_ALERT
    c.	Sudo systemctl restart snort
7.	Tambahkan rules untuk mendeteksi serangan DDoS ke file /etc/snort/rules/local.rules rules bisa didapatkan di file Snort_ddos_rule
8.	Tambahkan Wazuh Agent connection to ids hanya ambil yang untuk snort ke file ossec.conf di agent1 dibawah bagian Log analysis
![image](https://github.com/user-attachments/assets/f618cc00-1df1-47da-b264-6c7bacccfd15)

9.	Restart wazuh-agent systemctl restart wazuh-agent
10.	Setelah agent terinstal pada masing-masing ketiga ubuntu tersebut, maka install Suricata IDS pada ubuntu misal untuk Suricata IDS yang terinstal di salah satu ubuntu diberi nama agent2. 
    a.	sudo add-apt-repository ppa:oisf/suricata-stable 
    b.	sudo apt-get update 
    c.	sudo apt-get install suricata -y
    d.	Edit Suricata setting pada /etc/suricata/suricata.yaml ubah di bagian
        Linux high speed capture support
        af-packet:
          - interface: enp0s3
        Interfance mewakili antarmuka jaringan yang ingin di pantau. Ganti nilainya dengan nama interface dari Ubuntu endpoint bisa di cek leawat ifconfig. 
    e.	Sudo systemctl restart snort
11.	Tambahkan rules untuk mendeteksi serangan DDoS ke file /etc/suricata/rules/local.rules rules bisa didapatkan di file Suricata_ddos_rule, restart Kembali suricata
12.	Tambahkan Wazuh Agent connection to ids hanya ambil yang untuk suricata ke file ossec.conf di agent2 didalam ossec_config
![image](https://github.com/user-attachments/assets/9255a1d1-639a-4741-8fb6-19260f19fe77)

13.	Restart wazuh-agent untuk agent2 systemctl restart wazuh-agent
14.	Setelah agent terinstal pada masing-masing ketiga ubuntu tersebut, maka install Zeek IDS pada ubuntu misal untuk Zeek IDS yang terinstall di salah satu ubuntu diberi nama agent3. 
    a.	echo 'debhttp://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list 
    b.	curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null 
    c.	sudo apt update 
    d.	sudo apt install zeek-6.0 
    e.	tambahkan file owlh.zeek dan detection.zeek pada folder /opt/zeek/share/zeek/site 
    f.	load script owlh.zeek dan detection.zeek pada file local.zeek dan tambahkan pula agar ouput nya menjadi json seperti gambar di bawah ini
         ![image](https://github.com/user-attachments/assets/f0306adc-e327-41ca-ab4e-686350e2c68b)
    
    g.	restart zeek dengan command zeekctl deploy
15.	Tambahkan Wazuh Agent connection to ids hanya ambil yang untuk zeek ke file ossec.conf di agent3 didalam ossec_config
   ![image](https://github.com/user-attachments/assets/210c1fc2-12d4-4e71-b568-63d276a70ee1)

16.	Restart wazuh-agent untuk agent3 systemctl restart wazuh-agent
17.	Tambahkan Zeek_ids_rule ke wazuh endpoint bisa diakses lewat wazuh-dashboard di bagian rules lalu ke custom rules maka akan ada file local.rules tambahkan ke file itu lalu save
18.	Restart wazuh manager
19.	Buat script python dan service
    a.	Tambahkan AlertCorrelationScripts pada folder /var/ossec/integrations
    b.	Lalu buat service salin service pada alert.service
    c.	Tambahkan AlertCorrelationRule pada file local.rules di wazuh ubuntu endpoint, bisa diakses lewat wazuh-dashboard di bagian rules lalu ke custom rules maka akan ada file local.rules
20.	Restart wazuh manager
21.	Buatlah Service untuk Script Python Di ubuntu yang sudah di install Wazuh Manager 
22.	Simulasi penyerangan bisa dilakukan pada melalui kali linux dengan menggunakan hping3
23.	Penginstalan banyak wazuh agent di tiap ubuntu endpoint merupakan system multi-agent



