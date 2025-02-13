rule TrojanDownloader_Win32_Cred_A_2147651813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cred.A"
        threat_id = "2147651813"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cred"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 64 00 76 00 62 00 65 00 61 00 63 00 6f 00 6e 00 2e 00 6e 00 65 00 74 00 2f 00 61 00 64 00 76 00 2e 00 70 00 68 00 70 00 3f 00 69 00 3d 00 [0-4] 26 00 72 00 6e 00 64 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 61 64 76 62 65 61 63 6f 6e 2e 6e 65 74 2f 61 64 76 2e 70 68 70 3f 69 3d [0-4] 26 72 6e 64 3d}  //weight: 1, accuracy: Low
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "SOFTWAC:\\TEMP\\" wide //weight: 1
        $x_1_5 = {8d 85 70 fe ff ff 50 ff d6 83 f8 ff 74 04 a8 10 74 31 8d 85 68 fd ff ff 50 ff d6 83 f8 ff 74 04 a8 10 74 1f 8d 85 58 fb ff ff 50 ff d6 83 f8 ff 74 04 a8 10 74 0d 8d 9d 50 f9 ff ff e8 17 fc ff ff 33 db 8b 35 ?? ?? ?? ?? 6a 01 8d 85 70 fe ff ff 50 8d 85 60 fc ff ff 50 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Cred_B_2147652630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cred.B"
        threat_id = "2147652630"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cred"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {61 00 64 00 76 00 2e 00 70 00 68 00 70 00 3f 00 69 00 3d 00 [0-10] 26 00 72 00 6e 00 64 00 3d 00}  //weight: 2, accuracy: Low
        $x_1_2 = {6d 61 69 6c 74 6f [0-5] 72 73 73 [0-5] 2e 78 6d 6c [0-5] 6a 61 76 61 73 63 72 69 70 74}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 52 75 6e 5c [0-5] 25 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 25 00 [0-5] 25 41 50 50 44 41 54 41 25 00}  //weight: 1, accuracy: Low
        $x_2_4 = {88 01 41 89 4d d0 38 19 75 e6 8b 4d ?? 68 ?? ?? ?? ?? 51 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

