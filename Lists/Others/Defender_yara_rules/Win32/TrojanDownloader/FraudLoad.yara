rule TrojanDownloader_Win32_Fraudload_A_2147603240_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fraudload.A"
        threat_id = "2147603240"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fraudload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 c0 8d 85 b0 f1 ff ff 50 ff 15 ?? ?? ?? ?? 89 85 58 ef ff ff 6a 00 8d 8d fc fd ff ff 51 8b 95 ac f1 ff ff 52 8b 85 c0 f3 ff ff 03 85 b8 f3 ff ff 50 8b 8d 58 ef ff ff 51 ff 15 ?? ?? ?? ?? 8b 95 58 ef ff ff 52 ff 15 ?? ?? ?? ?? 8b 85 b8 f3 ff ff 03 85 ac f1 ff ff 89 85 b8 f3 ff ff e9 f2 fe ff ff 68 ?? ?? ?? ?? 8d 8d c8 f5 ff ff 51 68 ?? ?? ?? ?? 8d 95 c8 f9 ff ff 52 ff 15 ?? ?? ?? ?? 83 c4 10 6a 05 8d 85 c8 f9 ff ff 50 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? b8 df 0a 00 00 8b e5 5d c2 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 1
        $x_1_3 = {47 45 54 20 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 25 73 2e 63 6f 6d 2f [0-16] 2e 70 68 70 3f 26 61 64 76 69 64 3d ?? ?? ?? ?? ?? ?? ?? ?? 26 75 3d 25 75 26 70 3d 25 75 20 25 73 25 73 2e 25 73 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_4 = {47 45 54 20 2f [0-16] 2e 70 68 70 3f 26 61 64 76 69 64 3d ?? ?? ?? ?? ?? ?? ?? ?? 26 75 3d 25 75 26 70 3d 25 75 20 25 73 25 73 2e 25 73 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_5 = "C:\\Program Files\\%s\\%s.exe" ascii //weight: 1
        $x_1_6 = "C:\\Program Files\\%s\\%s.lic" ascii //weight: 1
        $x_1_7 = {50 72 6f 78 79 53 65 72 76 65 72 00 50 72 6f 78 79 45 6e 61 62 6c 65}  //weight: 1, accuracy: High
        $x_1_8 = {50 72 61 67 6d 61 3a 20 6e 6f 2d 63 61 63 68 65 0d 25 73 43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 6e 6f 2d 63 61 63 68 65 0d 25 73 0d 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Fraudload_B_2147603706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fraudload.B"
        threat_id = "2147603706"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fraudload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 c0 8d 85 b0 f1 ff ff 50 ff 15 ?? ?? ?? ?? 89 85 58 ef ff ff 6a 00 8d 8d fc fd ff ff 51 8b 95 ac f1 ff ff 52 8b 85 c0 f3 ff ff 03 85 b8 f3 ff ff 50 8b 8d 58 ef ff ff 51 ff 15 ?? ?? ?? ?? 8b 95 58 ef ff ff 52 ff 15 ?? ?? ?? ?? 8b 85 b8 f3 ff ff 03 85 ac f1 ff ff 89 85 b8 f3 ff ff e9 f2 fe ff ff 68 ?? ?? ?? ?? 8d 8d c8 f5 ff ff 51 68 ?? ?? ?? ?? 8d 95 c8 f9 ff ff 52 ff 15 ?? ?? ?? ?? 83 c4 10 6a 05 8d 85 c8 f9 ff ff 50 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? b8 df 0a 00 00 8b e5 5d c2 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Program Files\\%s\\%s.lic" ascii //weight: 1
        $x_1_3 = "C:\\Program Files\\%s\\%s.exe" ascii //weight: 1
        $x_1_4 = {25 73 20 2f [0-16] 2e 70 68 70 3f 26 25 73 ?? ?? ?? ?? ?? ?? ?? ?? 26 75 3d 25 75 26 70 3d 25 75 20 25 73 [0-32] 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_5 = {25 73 43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 6e 6f 2d 63 61 63 68 65 0d 25 73 0d 25 73}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 20 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 25 73 2e 63 6f 6d 2f [0-16] 2e 70 68 70 3f 25 73 ?? ?? ?? ?? ?? ?? ?? ?? 26 75 3d 25 75 26 70 3d 25 75 20 25 73 [0-32] 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_7 = {50 72 6f 78 79 53 65 72 76 65 72 00 50 72 6f 78 79 45 6e 61 62 6c 65}  //weight: 1, accuracy: High
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Fraudload_A_2147605151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fraudload.gen!A"
        threat_id = "2147605151"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fraudload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 c0 8d 85 b0 f1 ff ff 50 ff 15 ?? ?? ?? ?? 89 85 58 ef ff ff 6a 00 8d 8d fc fd ff ff 51 8b 95 ac f1 ff ff 52 8b 85 c0 f3 ff ff 03 85 b8 f3 ff ff 50 8b 8d 58 ef ff ff 51 ff 15 ?? ?? ?? ?? 8b 95 58 ef ff ff 52 ff 15 ?? ?? ?? ?? 8b 85 b8 f3 ff ff 03 85 ac f1 ff ff 89 85 b8 f3 ff ff e9 f2 fe ff ff 68 ?? ?? ?? ?? 8d 8d c8 f5 ff ff 51 68 ?? ?? ?? ?? 8d 95 c8 f9 ff ff 52 ff 15 ?? ?? ?? ?? 83 c4 10 6a 05 8d 85 c8 f9 ff ff 50 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? b8 df 0a 00 00 8b e5 5d c2 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Program Files\\%s\\%s.lic" ascii //weight: 1
        $x_1_3 = "C:\\Program Files\\%s\\%s.exe" ascii //weight: 1
        $x_1_4 = {50 72 6f 78 79 53 65 72 76 65 72 00 50 72 6f 78 79 45 6e 61 62 6c 65}  //weight: 1, accuracy: High
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 1
        $x_1_6 = "AntiSpywareShield" ascii //weight: 1
        $x_1_7 = "http://download.%s.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Fraudload_H_2147642423_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fraudload.H"
        threat_id = "2147642423"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fraudload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 74 68 65 73 65 6e 68 65 72 50 72 68 62 75 67 67 68 49 73 44 65 8b c4 50}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 0c 6a 41 68 63 75 74 65 68 6c 45 78 65 68 53 68 65 6c 8b c4 50 ff 35}  //weight: 1, accuracy: High
        $x_1_3 = {6a 64 68 46 6f 75 6e 8b c4 68 10 10 00 00 68 1e 30 40 00 50 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {57 65 27 72 65 20 70 72 6f 62 61 62 6c 79 20 75 6e 64 65 72 20 57 69 6e 39 38 00}  //weight: 1, accuracy: High
        $x_1_5 = {4f 70 65 4e 00 47 65 74 54 65 6d 70 50 61 74 68 41 00 50 72 65 73 65 6e 74 00 4e 4f 54 20 46 6f 75 6e 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Fraudload_I_2147642426_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fraudload.I"
        threat_id = "2147642426"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fraudload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ff 55 8d 4a 64 51 b9 40 00 00 00 51 ba 00 10 00 00 52 bf 80 05 00 00 57 bb 00 00 00 00 53 e8 7b 02 00 00 59 89 41 d0 8d b8 56 ff ff ff bb 36 10 40 00 33 f6 81 fe 80 05 00 00 74 28 83 c6 04 83 c3 04 8b 43 fc 89 87 aa 00 00 00 83 c7 04 81 87 a6 00 00 00 46 8e 1f d4 81 b7 a6 00 00 00 5c 2a 74 4e eb d0}  //weight: 1, accuracy: High
        $x_1_2 = {92 f2 80 c3 48 26 b6 0f 1a 4c 2a 1e cc b5 f9 1b a3 50 9e 53 f4 70 26 6b ef 61}  //weight: 1, accuracy: High
        $x_1_3 = {81 76 08 8b 4e 86 d9 23 d7 fb ff 00 f4 08 e0 65 dc 56 7b 1d fe 3e b9 b9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Fraudload_M_2147660249_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fraudload.M"
        threat_id = "2147660249"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fraudload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 11 6a 02 33 f6 6a 02 89 74 24 58 e8 ?? ?? ?? ?? 8b 54 24 58 8b 4c 24 54 8b e8 b8 02 00 00 00 52 66 89 44 24 34 89 4c 24 38 e8 ?? ?? ?? ?? 8d 4c 24 14 66 89 44 24 32}  //weight: 1, accuracy: Low
        $x_1_2 = "4E87B70E-64B9-4439-AFE1-F23C7AA006A6" ascii //weight: 1
        $x_1_3 = "EE54DB35-D1B0-458a-80B2-4E738EAD5109" ascii //weight: 1
        $x_1_4 = {00 70 72 75 75 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 70 72 65 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 57 61 72 6e 69 6e 67 2d 3e 48 74 74 70 50 6f 73 74 2d 3e 53 65 71 46 6c 61 67 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

