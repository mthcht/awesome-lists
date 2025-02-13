rule PWS_Win32_Dyzap_A_2147687905_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.A"
        threat_id = "2147687905"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\DYRE\\Release\\zapuskator" ascii //weight: 1
        $x_1_2 = ".\\pipe\\RangisPipe" wide //weight: 1
        $x_1_3 = "AUTOBACKCONN" ascii //weight: 1
        $x_1_4 = "=RBSG_CORP4P&domain=" ascii //weight: 1
        $x_1_5 = {48 83 ec 20 ff 55 08 48 8b 4d cc 48 8d 64 cc 20 5f 48 89 45 f4 e8 00 00 00 00 c7 44 24 04 23 00 00 00 83 04 24 0d cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_Dyzap_A_2147687905_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.A"
        threat_id = "2147687905"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 54 8f 45 f0 e8 00 00 00 00 c7 44 24 04 23 00 00 00 83 04 24 0d cb 8d 85 b0 fd ff ff 8b c8 89 45 fc 85 c9}  //weight: 1, accuracy: High
        $x_1_2 = {8a 07 3c ff 75 0d 80 7f 01 25 75 07 8b 47 02 8b 00 eb 19 3c e9 75 09 8b 4f 01 8d 44 39 05 eb 0c 3c eb 75 0f 0f be 57 01 8d 44 3a 02}  //weight: 1, accuracy: High
        $x_1_3 = {8b 54 24 2c 89 4c 24 ?? 39 51 44 0f 85 ?? ?? 00 00 89 7c 24 1c 39 79 04 0f 86 ?? ?? 00 00 8d 81 dc 00 00 00 89 44 24 ?? eb 07 8d a4 24 00 00 00 00 83 78 10 05 0f 85 ?? ?? 00 00 8b 30 57 ff 15 ?? ?? ?? 00 56 57 6a 10}  //weight: 1, accuracy: Low
        $x_1_4 = {62 74 6e 74 00 00 00 00 73 6c 69 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 41 55 54 4f 42 41 43 4b 43 4f 4e 4e 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 73 6f 00 2e 74 6b 00 2e 63 6e 00 2e 68 6b 00 2e 69 6e 00 2e 74 6f 00 2e 77 73 00 2e 63 63 00}  //weight: 1, accuracy: High
        $x_1_7 = {3c 72 70 63 69 00 00 00 3c 2f 72 70 63 69 3e 00 3f 63 69 64 3d 25 73 00 73 6f 75 72 63 65 68 74}  //weight: 1, accuracy: High
        $x_1_8 = {6e 6f 74 5f 73 75 70 70 6f 72 74 00 6c 6f 67 70 6f 73 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {73 65 6e 64 20 62 72 6f 77 73 6e 61 70 73 68 6f 74 20 66 61 69 6c 65 64 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 2f 25 73 2f 25 73 2f 25 64 2f 25 73 2f 25 73 2f 00}  //weight: 1, accuracy: High
        $x_1_11 = {3d 00 3d 00 47 00 65 00 6e 00 65 00 72 00 61 00 6c 00 3d 00 3d 00 0d 00 0a 00 00 00 3d 00 3d 00 55 00 73 00 65 00 72 00 73 00 3d 00 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_Dyzap_B_2147687920_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.B"
        threat_id = "2147687920"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\DYRE\\Release\\dyrecontroller.pdb" ascii //weight: 1
        $x_1_2 = "\\\\.\\pipe\\RangisPipe" wide //weight: 1
        $x_1_3 = "/%s/%s/5/publickey/" ascii //weight: 1
        $x_1_4 = {64 00 65 00 66 00 63 00 6f 00 6e 00 66 00 69 00 67 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Dyzap_C_2147687922_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.C"
        threat_id = "2147687922"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\DYRE\\Release\\iebattle.pdb" ascii //weight: 1
        $x_1_2 = "\\\\.\\pipe\\RangisPipe" wide //weight: 1
        $x_1_3 = "/%s/%s/14/error/%s" ascii //weight: 1
        $x_1_4 = {3c ff 75 0d 80 7f 01 25 75 07 8b 47 02 8b 00 eb 19 3c e9 75 09 8b 4f 01 8d 44 39 05 eb 0c 3c eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Dyzap_D_2147688302_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.D"
        threat_id = "2147688302"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DYRE" ascii //weight: 1
        $x_1_2 = "payload64" wide //weight: 1
        $x_1_3 = {57 67 65 74 2f 31 2e 39 00}  //weight: 1, accuracy: High
        $x_1_4 = "BotInfo: %s" ascii //weight: 1
        $x_1_5 = "AUTOBACKCONN" ascii //weight: 1
        $x_1_6 = "logkeys" ascii //weight: 1
        $x_1_7 = {64 00 65 00 66 00 63 00 6f 00 6e 00 66 00 69 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%" ascii //weight: 1
        $x_1_9 = "222289DD-9234-C9CA-94E3-E60D08C77777" ascii //weight: 1
        $x_1_10 = "botid" ascii //weight: 1
        $x_1_11 = {62 72 6f 77 73 6e 61 70 73 68 6f 74 00}  //weight: 1, accuracy: High
        $x_1_12 = "X-Forwarded-For: %s" ascii //weight: 1
        $x_9_13 = {48 83 ec 20 ff 55 08 48 8b 4d cc 48 8d 64 cc 20 5f 48 89 45 f4 e8 00 00 00 00 c7 44 24 04 23 00 00 00 83 04 24 0d cb}  //weight: 9, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_1_*))) or
            ((1 of ($x_9_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Dyzap_F_2147689499_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.F"
        threat_id = "2147689499"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 0f 0f b6 16 8a 4c 14 38 88 0e 48 46 85 c0 7f f1}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e9 10 25 00 00 ff ff 0b c1 33 d2 b9 19 00 00 00 f7 f1 8d 42 41 66 0f be d0 66 89 14 77 46 83 fe 0f}  //weight: 1, accuracy: High
        $x_1_3 = "qwererthwebfsdvjaf+" ascii //weight: 1
        $x_1_4 = {eb 0a 33 c9 c6 00 05 eb 05 0f 23 c0 eb f9}  //weight: 1, accuracy: High
        $x_1_5 = {6a 33 c1 e2 00 c1 cf 00 e8 00 00 00 00 83 04 24 09 87 ed 87 e4 cb}  //weight: 1, accuracy: High
        $x_1_6 = {c6 02 da eb 05 0f 22 c0 eb f9}  //weight: 1, accuracy: High
        $x_1_7 = {eb 0b 33 d2 c6 02 da 90 eb 05 0f 22 c0 eb f9}  //weight: 1, accuracy: High
        $x_1_8 = {85 c0 74 10 ff 37 83 ef 08 c1 cf 00 c1 fe 00 83 e8 01 eb ec}  //weight: 1, accuracy: High
        $x_1_9 = {8d 45 f4 99 52 50 6a 00 6a 00 8d 45 e4 99 52 8b 55 08 50 51 52 6a 04 56 57}  //weight: 1, accuracy: High
        $x_1_10 = {30 14 31 40 83 f8 08 72 02 33 c0 41 3b cf 72}  //weight: 1, accuracy: High
        $x_1_11 = {30 1c 30 41 83 f9 08 72 02 33 c9 40 3b c7 72}  //weight: 1, accuracy: High
        $x_1_12 = {68 b8 0b 00 00 ff d1 8b 86 ?? ?? ?? ?? 8d 95 dc fc ff ff 52 c7 85 ?? ?? ?? ?? 73 65 78 65 ff d0 8d 4c 00 02}  //weight: 1, accuracy: Low
        $x_1_13 = {8b 8e d8 00 00 00 ff d1 5f b8 39 01 00 c0}  //weight: 1, accuracy: High
        $x_1_14 = {0f 22 c0 0f 30 bf 08 00 00 00 eb 04 0f 32 74}  //weight: 1, accuracy: High
        $x_1_15 = {5f 48 89 45 ?? e8 00 00 00 00 c7 44 24 04 23 00 00 00 83 04 24 0d cb}  //weight: 1, accuracy: Low
        $x_1_16 = {30 04 11 42 8b 46 ?? 3b d0 72 ef}  //weight: 1, accuracy: Low
        $x_1_17 = {80 7a 02 64 75 10 80 7a 01 73 75 0a 80 3a 2e 75 05 8b 6a 0c 03 e8 47 83 c2 28 3b f9 7c ca}  //weight: 1, accuracy: High
        $x_1_18 = {8b 86 d8 00 00 00 ff d0 b8 39 01 00 c0 5e}  //weight: 1, accuracy: High
        $x_1_19 = {81 ff c8 00 00 00 7d 18 8b 8e 00 01 00 00 6a 64 ff d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Dyzap_J_2147689939_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.J"
        threat_id = "2147689939"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e3 ff 00 00 00 0f b6 9b ?? ?? ?? ?? 33 14 9d ?? ?? ?? ?? 03 c1 89 16 03 f1 ff 4d f8 75 ?? 4f 83 e8 20}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 06 0e 00 00 00 89 46 04 83 c1 02 0f b6 79 01 0f b6 19 c1 e7 08 0b fb 0f b6 59 ff c1 e7 08 0b fb 0f b6 59 fe c1 e7 08 0b fb 89 3c 90 42 83 c1 04 83 fa 08}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 58 0d 0f b6 40 0c c1 e7 08 0b fb c1 e7 08 0b f8 33 79 0c 8b 45 08 83 c1 10 83 7d 0c 00 89 7d f8 0f 85 ?? ?? ?? ?? 8b 18 d1 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Dyzap_J_2147689939_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.J"
        threat_id = "2147689939"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 e3 ff 00 00 00 0f b6 9b ?? ?? ?? ?? 33 14 9d ?? ?? ?? ?? 03 c1 89 16 03 f1 ff 4d f8 75 ?? 4f 83 e8 20}  //weight: 5, accuracy: Low
        $x_1_2 = "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X" ascii //weight: 1
        $x_1_3 = "AUTOBACKCONN" ascii //weight: 1
        $x_1_4 = "send browser snapshot failed" ascii //weight: 1
        $x_1_5 = "send system info failed" ascii //weight: 1
        $x_1_6 = "stun1.voiceeclipse.net" wide //weight: 1
        $x_1_7 = "http://icanhazip.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Dyzap_J_2147689939_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.J"
        threat_id = "2147689939"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X" ascii //weight: 1
        $x_1_2 = {62 6f 74 69 64 00 00 00 62 74 69 64 00 00 00 00 63 63 73 72 00 00 00 00 64 70 73 72 00 00 00 00 62 74 6e 74 00 00 00 00 73 6c 69 70}  //weight: 1, accuracy: High
        $x_1_3 = "AUTOBACKCONN" ascii //weight: 1
        $x_1_4 = "send browser snapshot failed" ascii //weight: 1
        $x_1_5 = "send system info failed" ascii //weight: 1
        $x_1_6 = "203.183.172.196:3478" wide //weight: 1
        $x_1_7 = "stun1.voiceeclipse.net" wide //weight: 1
        $x_1_8 = "http://icanhazip.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Dyzap_H_2147689953_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.H"
        threat_id = "2147689953"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {73 69 6b 65 73 76 63 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_5_2 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_1_3 = {89 4d e8 89 45 ec 6a 33 e8 00 00 00 00 83 04 24 05 cb}  //weight: 1, accuracy: High
        $x_1_4 = {6a 33 8b ff e8 00 00 00 00 83 04 24 09 8b ff 90 90 cb}  //weight: 1, accuracy: High
        $x_1_5 = {83 e4 f8 6a 33 f3 90 e8 00 00 00 00 83 04 24 09 8b ff f3 90 cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Dyzap_M_2147691054_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.M"
        threat_id = "2147691054"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 16 8a 8c 15 00 ff ff ff 88 0e 48 46 85 c0 7f}  //weight: 5, accuracy: High
        $x_5_2 = "Google Update Service" wide //weight: 5
        $x_1_3 = "ZwQueueApcThread" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = {89 4c 24 14 39 51 44 0f 85 fe 00 00 00 89 7c 24 1c 39 79 04 0f 86 f1 00 00 00 8d 81 dc 00 00 00 89 44 24 20 eb 07}  //weight: 1, accuracy: High
        $x_1_6 = {89 4c 24 14 39 51 44 0f 85 ff 00 00 00 83 79 04 00 c7 44 24 1c 00 00 00 00 0f 86 ed 00 00 00 8d 81 dc 00 00 00 89 44 24 20}  //weight: 1, accuracy: High
        $x_1_7 = {39 51 44 0f 85 ff 00 00 00 83 79 04 00 c7 44 24 1c 00 00 00 00 0f 86 ed 00 00 00 8d 81 dc 00 00 00 89 44 24 20}  //weight: 1, accuracy: High
        $x_1_8 = {8b 4c 24 04 83 79 64 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Dyzap_N_2147691941_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.N"
        threat_id = "2147691941"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 85 c0 74 15 8d 8d 40 fa ff ff 51 8d 85 10 fd ff ff e8 ?? ?? ?? ?? 83 c4 04 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d7 52 8d 85 ?? ?? ?? ?? 33 c9 50 66 89 4d ?? ff d3 68 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? 51 ff d3 8d 95}  //weight: 1, accuracy: Low
        $x_1_3 = {67 00 6f 00 6f 00 67 00 6c 00 65 00 75 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "ZwQueueApcThread: error code = %" wide //weight: 1
        $x_1_5 = {2e 00 65 00 78 00 65 00 00 00 00 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 00 00 4c 00 6f 00 63 00 61 00 6c 00 00 00 5c 00 00 00 00 00 00 00 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 53 00 6f 00}  //weight: 1, accuracy: High
        $x_1_7 = "Global\\zx5fwtw4ep" wide //weight: 1
        $x_1_8 = {89 5c 24 14 39 5e 04 0f 86 ba 00 00 00 8d 9e dc 00 00 00 83 7b 10 05 0f 85 82 00 00 00 83}  //weight: 1, accuracy: High
        $x_1_9 = {69 72 74 75 61 6c 41 6c 6c 6f 63 00 02 00 00 (41|2d|55|57|2d|5a)}  //weight: 1, accuracy: Low
        $x_1_10 = {3d 31 04 00 00 75 2c 68 ff 01 0f 00 e8}  //weight: 1, accuracy: High
        $x_1_11 = {8d 45 f4 99 52 50 6a 00 6a 00 8d 45 e4 99 52 8b 55 08 50 51 52 6a 04 56}  //weight: 1, accuracy: High
        $x_1_12 = {51 eb 17 eb 15 47 65 74 53 79 73 74 65 6d 50 6f}  //weight: 1, accuracy: High
        $x_1_13 = {eb 0f 50 ff d7 8b 74 24 10 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_Dyzap_B_2147692408_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.B!!Dyzap.gen!A"
        threat_id = "2147692408"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        info = "Dyzap: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 54 8f 45 f0 e8 00 00 00 00 c7 44 24 04 23 00 00 00 83 04 24 0d cb 8d 85 b0 fd ff ff 8b c8 89 45 fc 85 c9}  //weight: 1, accuracy: High
        $x_1_2 = {8a 07 3c ff 75 0d 80 7f 01 25 75 07 8b 47 02 8b 00 eb 19 3c e9 75 09 8b 4f 01 8d 44 39 05 eb 0c 3c eb 75 0f 0f be 57 01 8d 44 3a 02}  //weight: 1, accuracy: High
        $x_1_3 = {8b 54 24 2c 89 4c 24 ?? 39 51 44 0f 85 ?? ?? 00 00 89 7c 24 1c 39 79 04 0f 86 ?? ?? 00 00 8d 81 dc 00 00 00 89 44 24 ?? eb 07 8d a4 24 00 00 00 00 83 78 10 05 0f 85 ?? ?? 00 00 8b 30 57 ff 15 ?? ?? ?? 00 56 57 6a 10}  //weight: 1, accuracy: Low
        $x_1_4 = {62 74 6e 74 00 00 00 00 73 6c 69 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 41 55 54 4f 42 41 43 4b 43 4f 4e 4e 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 73 6f 00 2e 74 6b 00 2e 63 6e 00 2e 68 6b 00 2e 69 6e 00 2e 74 6f 00 2e 77 73 00 2e 63 63 00}  //weight: 1, accuracy: High
        $x_1_7 = {3c 72 70 63 69 00 00 00 3c 2f 72 70 63 69 3e 00 3f 63 69 64 3d 25 73 00 73 6f 75 72 63 65 68 74}  //weight: 1, accuracy: High
        $x_1_8 = {6e 6f 74 5f 73 75 70 70 6f 72 74 00 6c 6f 67 70 6f 73 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {73 65 6e 64 20 62 72 6f 77 73 6e 61 70 73 68 6f 74 20 66 61 69 6c 65 64 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 2f 25 73 2f 25 73 2f 25 64 2f 25 73 2f 25 73 2f 00}  //weight: 1, accuracy: High
        $x_1_11 = {3d 00 3d 00 47 00 65 00 6e 00 65 00 72 00 61 00 6c 00 3d 00 3d 00 0d 00 0a 00 00 00 3d 00 3d 00 55 00 73 00 65 00 72 00 73 00 3d 00 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_Dyzap_A_2147692410_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.A!!Dyzap.gen!A"
        threat_id = "2147692410"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        info = "Dyzap: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X" ascii //weight: 1
        $x_1_2 = {62 6f 74 69 64 00 00 00 62 74 69 64 00 00 00 00 63 63 73 72 00 00 00 00 64 70 73 72 00 00 00 00 62 74 6e 74 00 00 00 00 73 6c 69 70}  //weight: 1, accuracy: High
        $x_1_3 = "AUTOBACKCONN" ascii //weight: 1
        $x_1_4 = "send browser snapshot failed" ascii //weight: 1
        $x_1_5 = "send system info failed" ascii //weight: 1
        $x_1_6 = "stun1.voiceeclipse.net" wide //weight: 1
        $x_1_7 = "icanhazip.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Dyzap_N_2147693273_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.N!!Dyzap.gen!B"
        threat_id = "2147693273"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        info = "Dyzap: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 85 c0 74 15 8d 8d 40 fa ff ff 51 8d 85 10 fd ff ff e8 ?? ?? ?? ?? 83 c4 04 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d7 52 8d 85 ?? ?? ?? ?? 33 c9 50 66 89 4d ?? ff d3 68 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? 51 ff d3 8d 95}  //weight: 1, accuracy: Low
        $x_1_3 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 75 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "ZwQueueApcThread: error code = %" wide //weight: 1
        $x_1_5 = {2e 00 65 00 78 00 65 00 00 00 00 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 00 00 4c 00 6f 00 63 00 61 00 6c 00 00 00 5c 00 00 00 00 00 00 00 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 53 00 6f 00}  //weight: 1, accuracy: High
        $x_1_7 = "Global\\zx5fwtw4ep" wide //weight: 1
        $x_1_8 = {89 5c 24 14 39 5e 04 0f 86 ba 00 00 00 8d 9e dc 00 00 00 83 7b 10 05 0f 85 82 00 00 00 83}  //weight: 1, accuracy: High
        $x_1_9 = {00 4d 69 72 74 75 61 6c 41 6c 6c 6f 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_Dyzap_Q_2147694112_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.Q"
        threat_id = "2147694112"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {64 a1 30 00 00 00 85 db 89 44 24 ?? 58 8b 44 24 ?? 83 78 64 02 0f 82}  //weight: 3, accuracy: Low
        $x_3_2 = {51 eb 17 eb 15 47 65 74 53 79 73 74 65 6d 50 6f 77 65 72 53 74 61 74 75 73 00 68 ?? ?? 40 00 8f 45 fc 8b 45 fc 8b e5 5d c3}  //weight: 3, accuracy: Low
        $x_3_3 = {69 72 74 75 61 6c 41 6c 6c 6f 63 00 02 00 00 (41|2d|55|57|2d|5a)}  //weight: 3, accuracy: Low
        $x_1_4 = {00 00 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 7a 00 78 00 35 00 66 00 77 00 74 00 77 00 34 00 65 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 70 00 65 00 6e 00 33 00 6a 00 33 00 38 00 33 00 32 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 47 6c 6f 62 61 6c 5c 70 65 6e 33 36 33 38 33 32 68 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Dyzap_R_2147694672_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.R"
        threat_id = "2147694672"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZwrueuerpcThread" ascii //weight: 1
        $x_1_2 = "-ZwQueueApcThread:" wide //weight: 1
        $x_1_3 = "googleupdate" wide //weight: 1
        $x_1_4 = "Update Service" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Dyzap_T_2147696961_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.T"
        threat_id = "2147696961"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 b8 61 00 00 00 b9 52 00 00 00 57 66 89 45 f0 66 89 4d ec ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 f3 75 c6 45 f7 6a ff 15 ?? ?? ?? ?? 85 c0 74 11}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d0 6a 04 68 00 30 00 00 68 00 00 02 00 6a 00 89 44 24 34 ff 54 24 28 8b f8}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 f0 50 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 4d 08 51 6a 00 68 08 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Dyzap_T_2147696961_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.T"
        threat_id = "2147696961"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d d4 ba 4b 76 41 02 c1 e6 00 c1 ec 00 48 8b 55 dc ff 75 e4}  //weight: 1, accuracy: High
        $x_1_2 = {c7 85 38 f2 ff ff 73 65 78 65 ff 15 ?? ?? ?? ?? 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {74 00 65 00 6d 00 70 00 00 00 00 00 67 00 75 00 70 00 64 00 61 00 74 00 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "Global\\u1nyj3rt20" ascii //weight: 1
        $x_1_5 = "\\\\.\\pipe\\g2fabg5713" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Dyzap_T_2147696961_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.T"
        threat_id = "2147696961"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d d4 ba 4b 76 41 02 c1 e6 00 c1 ec 00 48 8b 55 dc ff 75 e4}  //weight: 1, accuracy: High
        $x_1_2 = {8d 45 f4 99 52 50 6a 00 6a 00 8d 45 e4 99 52 8b 55 08 50 51 52 6a 04 56 57}  //weight: 1, accuracy: High
        $x_1_3 = {74 00 65 00 6d 00 70 00 00 00 00 00 67 00 75 00 70 00 64 00 61 00 74 00 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "Global\\t1nyj3rt20" ascii //weight: 1
        $x_1_5 = "\\\\.\\pipe\\g2fabg5713" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Dyzap_V_2147706906_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.V"
        threat_id = "2147706906"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 96 fe fe ff 7f 85 d2 74 22 0f b7 14 0f 66 85 d2 74 19 66 89 11 83 c1 02 4e 75 e4}  //weight: 1, accuracy: High
        $x_1_2 = {2e 73 6f 00 2e 74 6b 00 2e 63 6e 00 2e 68 6b 00 2e 69 6e}  //weight: 1, accuracy: High
        $x_1_3 = {76 6e 63 74 00 00 00 00 67 76 6e 63}  //weight: 1, accuracy: High
        $x_1_4 = {43 6c 69 65 6e 74 53 65 74 4d 6f 64 75 6c 65 00 56 6e 63 53 74 61 72 74 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 73 00 5c 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 00 00 00 00 66 00 69 00 6c 00 65 00 2e 00 64 00 61 00 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Dyzap_X_2147717189_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dyzap.X"
        threat_id = "2147717189"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyzap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 87 00 04 00 00 ef be ad de c7 87 58 04 00 00 00 00 00 00 66 89 1f c7 47 3c 40 00 00 00 c7 47 40 50 45 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 2c 11 41 33 e8 81 e5 ff 00 00 00 c1 e8 08 33 04 ac 3b cb 7c e9}  //weight: 1, accuracy: High
        $x_1_3 = {8b c8 6a 2a e8 ?? ?? ?? ?? 8b c8 6a 2e e8 ?? ?? ?? ?? 8b c8 6a 65 e8 ?? ?? ?? ?? 8b c8 6a 78 e8 ?? ?? ?? ?? 8b c8 6a 65}  //weight: 1, accuracy: Low
        $x_1_4 = {31 2c b8 47 3b fa 7c f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

