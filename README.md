# Integration-IDS-With-Siem

Dokumentasi Teknis TA

## Langkah-Langkah Instalasi

### 1. Persiapan
1. Install virtual machine seperti VirtualBox atau VMware.
2. Siapkan 4 mesin Ubuntu di dalam virtual machine.

### 2. Instalasi Wazuh Manager
1. Install Wazuh pada salah satu Ubuntu. Pastikan mesin ini memenuhi sistem persyaratan untuk Wazuh.

    ```bash
    curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
    ```

    ![image](https://github.com/user-attachments/assets/ef29a9e5-56c8-4828-9ab6-6819edd24989)


2. Buka Wazuh dashboard pada browser dan login dengan username serta password yang diberikan setelah instalasi selesai.

### 3. Instalasi Wazuh Agent
1. Install Wazuh Agent pada tiga Ubuntu lainnya.
2. Tambahkan agent baru di Wazuh dashboard dan ikuti instruksi yang diberikan untuk instalasi agent.

### 4. Instalasi Snort IDS
1. Install Snort IDS pada salah satu Ubuntu (misalnya, agent1):

    ```bash
    sudo apt-get install snort -y
    ```

2. Edit file konfigurasi Snort:

    ```bash
    sudo nano /etc/snort/snort.conf
    ```
   - Scroll ke bagian step 6 dan uncomment baris `output alert_syslog: LOG_AUTH LOG_ALERT`.

3. Restart Snort:

    ```bash
    sudo systemctl restart snort
    ```

4. Tambahkan aturan untuk mendeteksi serangan DDoS pada file:

    ```bash
    /etc/snort/rules/local.rules
    ```

5. Tambahkan konfigurasi Snort ke file `ossec.conf` di agent1 di bagian **Log analysis**.

    ![image](https://github.com/user-attachments/assets/2ef08224-d7fa-4556-b0f9-4224b70b28c7)

6. Restart Wazuh Agent:

    ```bash
    sudo systemctl restart wazuh-agent
    ```

### 5. Instalasi Suricata IDS
1. Install Suricata pada salah satu Ubuntu (misalnya, agent2):

    ```bash
    sudo add-apt-repository ppa:oisf/suricata-stable 
    sudo apt-get update 
    sudo apt-get install suricata -y
    ```

2. Edit file konfigurasi Suricata:

    ```bash
    sudo nano /etc/suricata/suricata.yaml
    ```
   - Ubah bagian berikut:

    ```yaml
    af-packet:
      - interface: <nama_interface>
    ```
   - Ganti `<nama_interface>` dengan nama interface jaringan yang ingin dipantau (dapat diperiksa dengan `ifconfig`).

3. Restart Suricata:

    ```bash
    sudo systemctl restart suricata
    ```

4. Tambahkan aturan DDoS pada file:

    ```bash
    /etc/suricata/rules/local.rules
    ```

5. Tambahkan konfigurasi Suricata ke file `ossec.conf` di agent2 di bagian **ossec_config**.

    ![image](https://github.com/user-attachments/assets/596a6619-60fd-4d4d-ae4f-0478c72d3560)

6. Restart Wazuh Agent:

    ```bash
    sudo systemctl restart wazuh-agent
    ```

### 6. Instalasi Zeek IDS
1. Install Zeek pada salah satu Ubuntu (misalnya, agent3):

    ```bash
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    sudo apt update
    sudo apt install zeek-6.0
    ```

2. Tambahkan file `owlh.zeek` dan `detection.zeek` ke folder:

    ```bash
    /opt/zeek/share/zeek/site
    ```

3. Muat script tersebut di file `local.zeek` dan tambahkan konfigurasi output JSON.

    ![image](https://github.com/user-attachments/assets/b0fd0e52-3ae7-4392-a403-9581a50ac7d5)

4. Restart Zeek:

    ```bash
    zeekctl deploy
    ```

5. Tambahkan konfigurasi Zeek ke file `ossec.conf` di agent3 di bagian **ossec_config**.

   ![image](https://github.com/user-attachments/assets/ce28fd42-d6ad-4c56-88c7-18ce77395674)

7. Restart Wazuh Agent:

    ```bash
    sudo systemctl restart wazuh-agent
    ```

### 7. Tambahkan Rules Custom ke Wazuh Endpoint
1. Tambahkan `Zeek_ids_rule` ke file **local.rules** melalui Wazuh dashboard di bagian **Custom Rules**.
2. Restart Wazuh Manager.

### 8. Pembuatan Script Python dan Service
1. Tambahkan `AlertCorrelationScripts.py` ke folder:

    ```bash
    /var/ossec/integrations
    ```

2. Buat service menggunakan file `alert.service`.
3. Tambahkan `AlertCorrelationRule` ke file **local.rules** di Wazuh Ubuntu endpoint melalui Wazuh dashboard.
4. Restart Wazuh Manager.

### 9. Simulasi Penyerangan
1. Gunakan Kali Linux untuk melakukan simulasi serangan dengan `hping3`.

### 10. Multi-Agent Configuration
1. Pastikan instalasi Wazuh Agent dilakukan pada setiap Ubuntu endpoint untuk konfigurasi sistem multi-agent.
