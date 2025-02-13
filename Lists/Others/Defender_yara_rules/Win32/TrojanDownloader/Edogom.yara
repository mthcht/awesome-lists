rule TrojanDownloader_Win32_Edogom_A_2147690137_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Edogom.gen!A"
        threat_id = "2147690137"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Edogom"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 24 56 8b 74 24 0c 57 8b 7c 24 14 2b f7 8d 0c 38 8a 14 0e 02 d0 80 ea 02 40 3b c5 88 11 7c ee 5f}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 d4 6a c6 45 d5 75 c6 45 d6 74 c6 45 d7 6f c6 45 d8 38 c6 45 d9 2c c6 45 da 2b c6}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 1a 63 c6 44 24 1b 71 c6 44 24 1c 67 c6 44 24 1d 6d c6 44 24 1e 70 c6 44 24 1f 39}  //weight: 1, accuracy: High
        $x_1_4 = {c6 44 24 60 4f c6 44 24 61 70 c6 44 24 62 7a c6 44 24 63 68 c6 44 24 64 6a c6 44 24 65 69 c6 44 24 66 5d c6 44 24 67 2a}  //weight: 1, accuracy: High
        $x_1_5 = {5c 64 65 73 6b 74 6f 70 73 2e 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Edogom_B_2147691408_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Edogom.B"
        threat_id = "2147691408"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Edogom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d fc de 00 00 00 76 20 33 c0 8b c8 8b 85 ?? ?? ff ff 03 c8 87 d9 33 c0 50 59 50 51 ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fa be 2f 00 00 73 18 8d 85 ?? ?? ff ff 50 8d 8d ?? ?? ff ff 51 e8 ?? ?? ?? ?? 83 c4 08 eb 24}  //weight: 1, accuracy: Low
        $x_1_3 = {04 12 2b 34 37 55 47 4a 28 6b 43 23 32 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Edogom_C_2147691414_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Edogom.C"
        threat_id = "2147691414"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Edogom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 70 7a 68 6a 69 5d 2a 2e 27 28 17 1e 58 63 60 62 52 64 58 50 59 51 14 00}  //weight: 1, accuracy: High
        $x_1_2 = {3e 74 63 71 67 6d 70 39 00}  //weight: 1, accuracy: High
        $x_1_3 = {3e 30 73 62 70 66 6c 6f 38 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 33 64 76 69 64 65 6f 2e 72 75 2f 6e 65 77 2f 33 64 2f [0-16] 2e 70 68 70 3f 70 6c 61 79 3d 31 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

