rule Trojan_Linux_CoinMiner_B_2147751830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CoinMiner.B!MTB"
        threat_id = "2147751830"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 f3 aa 48 8b 7d 00 e8 38 10 00 00 31 ff e8 fa 1c 00 00 48 89 c3 e8 63 1d 00 00 8d 3c 18 e8 52 09 00 00 e8 ae 04 00 00 be 41 00 00 00 31 c0}  //weight: 1, accuracy: High
        $x_1_2 = "/tmp/.systemd.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_CoinMiner_P_2147763876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CoinMiner.P!MTB"
        threat_id = "2147763876"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {63 75 72 6c 20 2d 6f 20 2f 74 6d 70 2f 2e 67 67 2f 74 6f 70 [0-21] 63 64 6e 2e 69 6e 74 65 72 61 6b 74 2e 6d 64 2f 74 6f 70 20 3e 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 20 64 6f 6e 65 3b}  //weight: 2, accuracy: Low
        $x_2_2 = "chmod +x /tmp/.gg/*" ascii //weight: 2
        $x_1_3 = "cd /tmp/.gg && rm -rf top x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_CoinMiner_2147764177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CoinMiner.ab!MTB"
        threat_id = "2147764177"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "ab: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chmod 777 %s;%s %s -l /tmp/%s.txt" ascii //weight: 1
        $x_1_2 = "stratum+tcp://" ascii //weight: 1
        $x_1_3 = "miner" ascii //weight: 1
        $x_1_4 = "Welcome to Satan DDoS!" ascii //weight: 1
        $x_1_5 = "Mode of infection FTP,IPC,SMB,WMI,MSSQL,EternalBlue" ascii //weight: 1
        $x_1_6 = "BlackSquidMining,SpreadMiner" ascii //weight: 1
        $x_1_7 = "postattack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Linux_CoinMiner_C_2147828137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CoinMiner.C!xp"
        threat_id = "2147828137"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 ed 48 89 e7 48 8d 35 f4 e9 bf ff 48 83 e4 f0 e8 ?? ?? ?? 00 48 8d 57 08 50 48 8b 37 4c 8d 05 5e b9 0c 00 48 8b 0d dd 38 44 00 45 31 c9 48 8d 3d 7b f6 ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8d 3d c7 45 44 00 48 8d 05 c7 45 44 00 55 48 29 f8 48 89 e5 48 83 f8 0e 76 0f 48 8b 05 9c 38 44 00 48 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_CoinMiner_D_2147828138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CoinMiner.D!xp"
        threat_id = "2147828138"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "spy-client.cpp" ascii //weight: 1
        $x_1_2 = "touch -r /bin/sh %s" ascii //weight: 1
        $x_1_3 = "chmod +x %s 1>/dev/null 2>" ascii //weight: 1
        $x_1_4 = "cp -f %s %s 1>/dev/null 2>" ascii //weight: 1
        $x_1_5 = "[kdmflush]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Linux_CoinMiner_A_2147828995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CoinMiner.A!xp"
        threat_id = "2147828995"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 82 00 c0 a1 49 29 08 22 14 20 40 23 08 69 00 00 00 40 01 13 a0 48 14 63 84 11 80 00 02 00 10 00 80 03 20 e2 0e 05 a8 11 00 41}  //weight: 1, accuracy: High
        $x_1_2 = {25 80 21 40 88 80 01 01 00 80 22 91 00 02 00 e4 08 d0 a5 11 ca 10 58 67 6e 38 06 20 40 84 20 40 21 41 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 d0 30 15 31 a2 97 a8 10 00 00 01 80 70 85 45 a0 54 e0 04 2d 06 8c a5 8a 10 01 8a 44 02 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_CoinMiner_R_2147842818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CoinMiner.R!MTB"
        threat_id = "2147842818"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "main.updateminer" ascii //weight: 5
        $x_1_2 = "crypto/curve25519" ascii //weight: 1
        $x_1_3 = "dirtyLocked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_CoinMiner_T_2147902245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CoinMiner.T!MTB"
        threat_id = "2147902245"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "scoped_message_writer.h" ascii //weight: 1
        $x_1_2 = "COMMAND_RPC_GETMINERDATA" ascii //weight: 1
        $x_1_3 = "i2p_addressEEE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_CoinMiner_AT_2147904543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CoinMiner.AT!MTB"
        threat_id = "2147904543"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lin_start_miner" ascii //weight: 1
        $x_1_2 = "lin_download_payload_and_exec" ascii //weight: 1
        $x_1_3 = "Get_miner_name" ascii //weight: 1
        $x_1_4 = "platform.lin_walk_cron" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_CoinMiner_AX_2147915802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CoinMiner.AX!MTB"
        threat_id = "2147915802"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 0d f9 0c 20 00 45 85 c9 75 ?? 45 31 d2 48 63 d2 48 63 ff b8 3d 00 00 00 0f 05 48 3d 00 f0 ff ff 77 ?? c3 48 c7 c2 fc ff ff ff f7 d8 64 89 02 48 83 c8 ff c3 53}  //weight: 1, accuracy: Low
        $x_1_2 = {64 48 c7 04 25 30 06 00 00 ff ff ff ff f0 64 83 0c 25 08 03 00 00 10 64 48 8b 3c 25 00 03 00 00 e8 bb f4 bf ff f4 66 2e 0f 1f 84 00 00 00 00 00 f7 c7 02 00 00 00 75 ?? 64 8b 04 25 08 03 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_CoinMiner_C12_2147941154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CoinMiner.C12"
        threat_id = "2147941154"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "xmrig" ascii //weight: 2
        $x_2_2 = "stratum+ssl" ascii //weight: 2
        $x_2_3 = "randomx" ascii //weight: 2
        $x_2_4 = "Monero" ascii //weight: 2
        $x_2_5 = "Kevacoin" ascii //weight: 2
        $x_2_6 = "Ravencoin" ascii //weight: 2
        $x_2_7 = "wownero" ascii //weight: 2
        $x_2_8 = "memory-pool" ascii //weight: 2
        $x_2_9 = "huge-pages" ascii //weight: 2
        $x_2_10 = "pool address" ascii //weight: 2
        $x_2_11 = "socks5://" ascii //weight: 2
        $x_2_12 = "stratum+tcp://" ascii //weight: 2
        $x_2_13 = "/nr_hugepages" ascii //weight: 2
        $x_2_14 = "cryptonight" ascii //weight: 2
        $x_2_15 = "mining.authorize" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

