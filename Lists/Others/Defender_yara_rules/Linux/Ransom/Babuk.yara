rule Ransom_Linux_Babuk_D_2147811833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.D!MTB"
        threat_id = "2147811833"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.decrypt_file" ascii //weight: 1
        $x_1_2 = "filepath.Walk" ascii //weight: 1
        $x_1_3 = "golang.org/x/crypto/chacha20" ascii //weight: 1
        $x_1_4 = "BABUK_LOCK" ascii //weight: 1
        $x_1_5 = "golang.org/x/crypto/curve25519" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_E_2147845996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.E!MTB"
        threat_id = "2147845996"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b 45 f0 48 83 c0 13 48 8d 15 aa ae 0b 00 48 89 d6 48 89 c7 e8 3c ef ff ff 85 c0 0f 84 fe 00 00 00 48 8b 45 f0 48 83 c0 13 48 8d 15 9b ae 0b 00 48 89 d6 48 89 c7 e8 9a ee ff ff 48 85 c0 0f 85 bd 00 00 00 8b 05 7b 07 0f 00 83 c0 01 89 05 72 07 0f 00 48 8b 55 c8 48 8b 45 d8 48 89 d6 48 89 c7 e8 af ed ff ff 48 8b 45 d8 48 89 c7 e8 43 ef ff ff 48 89 c2 48 8b 45 d8 48 01 d0 66 c7 00 2f 00 48 8b 45 f0 48 8d 50 13 48 8b 45 d8 48 89 d6 48 89 c7 e8 fd ed ff ff 48 8b 45 d8 48 89 c7 e8 11 ef ff ff 48 83 c0 01 48 89 c7 e8 e5 a6 02 00 48 89 45 f8 48 8b 55 d8 48 8b 45 f8 48 89 d6 48 89 c7 e8 4e ed ff ff 48 8b 45 f8 48 89 c6 48 8d 05 ff ad 0b 00 48 89 c7 b8 00 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "/path/to/be/encrypted" ascii //weight: 1
        $x_1_3 = "bestway4u@mailfence.com" ascii //weight: 1
        $x_1_4 = "bestway4u@onionmail.com" ascii //weight: 1
        $x_1_5 = "Cylance Ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Linux_Babuk_B_2147846672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.B!MTB"
        threat_id = "2147846672"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 73 61 67 65 3a 20 25 73 [0-7] 2f 74 6f 2f 62 65 2f 65 6e 63 [0-2] 79 70 74 65 64}  //weight: 1, accuracy: Low
        $x_1_2 = ".vmdk" ascii //weight: 1
        $x_1_3 = ".vswp" ascii //weight: 1
        $x_1_4 = "Encrypted files:" ascii //weight: 1
        $x_1_5 = "Skipped files:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_C_2147895099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.C!MTB"
        threat_id = "2147895099"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".x1nGx1nG" ascii //weight: 1
        $x_1_2 = "vim-cmd vmsvc/getallvms" ascii //weight: 1
        $x_1_3 = "kph29siuk8@skiff.com" ascii //weight: 1
        $x_1_4 = "vim-cmd vmsvc/power.shutdown %s" ascii //weight: 1
        $x_1_5 = "===[ To Restore Files ]===.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_F_2147901929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.F!MTB"
        threat_id = "2147901929"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 05 4e b6 00 00 48 89 c7 e8 f6 f7 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "path/to/be/encrypted" ascii //weight: 1
        $x_1_3 = {48 8d 05 4a b6 00 00 48 89 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_G_2147904438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.G!MTB"
        threat_id = "2147904438"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files are encrypted" ascii //weight: 1
        $x_1_2 = "CYLANCE_README.txt" ascii //weight: 1
        $x_1_3 = "/path/to/be/encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_M_2147909482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.M"
        threat_id = "2147909482"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Buongiorno la mia bella Italia" ascii //weight: 1
        $x_1_2 = "Welcome to the RansomHouse" ascii //weight: 1
        $x_1_3 = "You are locked by" ascii //weight: 1
        $x_1_4 = "W H I T E  R A B B I T" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_I_2147911020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.I!MTB"
        threat_id = "2147911020"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 2c 8b 45 0c 8b 55 f4 89 54 24 0c 89 44 24 08 c7 44 24 04 01 00 00 00 8b 45 08 89 04 24 e8 4f fe ff ff 8b 45 f4 89 04 24 e8 f4 fc ff ff c9}  //weight: 1, accuracy: High
        $x_1_2 = {55 89 e5 53 83 ec 34 8b 45 08 89 45 e0 8b 45 0c 89 45 e4 b8 14 00 00 00 89 04 24 e8 a2 fd ff ff 89 45 e8 c7 45 f0 00 00 00 00 c7 45 f4 00 00 00 10 c7 45 ec 00 00 00 00 e9 fd 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_PC_2147916874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.PC!MTB"
        threat_id = "2147916874"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".diskhelpyou" ascii //weight: 1
        $x_1_2 = "/How To Restore Your Files.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_J_2147919775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.J!MTB"
        threat_id = "2147919775"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.encrypt_file_full" ascii //weight: 1
        $x_1_2 = "DATAF L**OCKER" ascii //weight: 1
        $x_1_3 = "hack to mainstream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_N_2147922771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.N!MTB"
        threat_id = "2147922771"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 10 48 8b 7c 24 20 48 8b 74 24 28 48 8b 54 24 30 48 8b 05 12 26 12 00 48 89 e3 48 83 e4 f0 ff d0 48 89 dc 89 44 24 38 48 83 c4 10 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 7c 24 08 48 8b 74 24 10 48 c7 c2 00 00 00 00 49 c7 c2 00 00 00 00 49 c7 c0 00 00 00 00 4c 8b 6c 24 18 4c 8b 4c 24 20 4c 8b 64 24 28 49 83 fd 00 74 18 49 83 f9 00 74 12 4d 8d 85 88 00 00 00 49 83 c0 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_AB_2147927973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.AB!MTB"
        threat_id = "2147927973"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 00 00 f0 00 60 08 91 01 00 40 f9 00 00 00 b0 03 a0 09 91 00 00 00 b0 02 e0 03 91 e0 17 40 f9 13 fe ff 97 80 00 00 f0 00 60 08 91 01 00 40 f9 00 00 00 b0 03 c0 09 91 00 00 00 b0 02 c0 05 91 e0 17 40 f9 0a fe ff 97 e0 1f 40 b9 1f 00 00 71 61 00 00 54 e0 17 40 f9 c1 e7 ff 97}  //weight: 1, accuracy: High
        $x_1_2 = {e0 3f 40 b9 1f 00 13 6b 22 fd ff 54 e1 27 40 f9 e0 03 15 2a 23 00 00 8b e0 03 14 2a e1 23 40 f9 20 00 00 8b e2 3f 40 b9 e1 03 00 aa e0 03 03 aa 91 fd ff 97 1f 20 03 d5 f3 53 41 a9 f5 13 40 f9 fd 7b c5 a8 c0 03 5f d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_O_2147928878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.O!MTB"
        threat_id = "2147928878"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 48 08 48 8b 8c 24 90 00 00 00 48 89 48 18 48 89 50 10 e8 b6 ff f8 ff 48 8b 4c 24 70 48 ff 01}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 48 83 ec 10 48 8b 7c 24 20 48 8b 74 24 28 48 8b 54 24 30 48 8b 05 f2 3d 13 00 48 89 e3 48 83 e4 f0 ff d0 48 89 dc 89 44 24 38 48 83 c4 10 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_K_2147928907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.K!MTB"
        threat_id = "2147928907"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "for i in $(esxcli vm process list" ascii //weight: 1
        $x_1_2 = "grep -Eo '[0-9]{1,8}'); do esxcli vm process kill -t=force -w=$i; done" ascii //weight: 1
        $x_1_3 = "for i in $(vim-cmd vmsvc/getallvms" ascii //weight: 1
        $x_1_4 = "grep -Eo '[0-9]{1,8}'); do vim-cmd vmsvc/snapshot.removeall $i; done" ascii //weight: 1
        $x_1_5 = "]]; then vim-cmd vmsvc/power.off $i; fi; done" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_L_2147933380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.L!MTB"
        threat_id = "2147933380"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".babyk" ascii //weight: 1
        $x_1_2 = "KillVM" ascii //weight: 1
        $x_1_3 = "vm-list.txt" ascii //weight: 1
        $x_1_4 = "Encrypting:" ascii //weight: 1
        $x_1_5 = "/README_TO_RESTORE.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_R_2147935129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.R!MTB"
        threat_id = "2147935129"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BadWeather Ransomware" ascii //weight: 1
        $x_1_2 = ".badweather" ascii //weight: 1
        $x_1_3 = ".bw_encryptionkey" ascii //weight: 1
        $x_1_4 = "BadWeather ESXI Encrypter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_Q_2147935545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.Q!MTB"
        threat_id = "2147935545"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.encrypt_file" ascii //weight: 1
        $x_1_2 = "Endpoint Ransomware" ascii //weight: 1
        $x_1_3 = "RsWare/nas_2/enc/main.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Babuk_T_2147947410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babuk.T!MTB"
        threat_id = "2147947410"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ensureAllVMsShutdown" ascii //weight: 1
        $x_1_2 = "encrypt_file" ascii //weight: 1
        $x_1_3 = ".q7gDPyOV7" ascii //weight: 1
        $x_1_4 = "ransom_note" ascii //weight: 1
        $x_1_5 = "esxcli vm process kill --type=force --world-id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

