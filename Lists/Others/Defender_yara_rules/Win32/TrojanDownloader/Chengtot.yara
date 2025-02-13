rule TrojanDownloader_Win32_Chengtot_A_2147606905_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chengtot.A"
        threat_id = "2147606905"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chengtot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 01 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 ff 35 ?? ?? ?? ?? 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 68 ?? ?? ?? 00 ff 35 ?? ?? ?? ?? 68 ?? ?? ?? 00 8d 45 fc ba 12 00 00 00 e8 ?? ?? fe ff 8b 45 fc 50 ff 35 ?? ?? ?? ?? 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 8d 45 f8 ba 06 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 [0-48] 3a 2f 2f [0-48] 64 72 [0-32] 76 [0-32] 33 32 [0-32] 2e [0-32] 64 61 74 61 [0-53] 2e 65 [0-32] 78 [0-32] 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Chengtot_B_2147607933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chengtot.B"
        threat_id = "2147607933"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chengtot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 00 00 [0-18] 74 00 [0-18] 70 00 [0-18] 3a 00 [0-18] 2f 00 [0-18] 77 00 [0-18] 6f 00 [0-18] 6c 00 [0-18] 63 00 [0-18] 6d 00 [0-18] 61 00 [0-18] 3f 00 [0-18] 71 00 [0-18] 3d 00 [0-32] 73 65 78 20 64 6f 77 6e 6c 6f 61 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Chengtot_B_2147607933_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chengtot.B"
        threat_id = "2147607933"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chengtot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 3e 0a 7e 05 83 3f 00 75 ?? e8 ?? b3 ff ff c7 06 01 00 00 00 83 3e 02 0f 85 ?? 03 00 00 c7 06 db 04 00 00 eb 1e 8b 07 50}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 01 68 ?? ?? ?? ?? ff 33 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 33 68 ?? ?? ?? ?? ff 33 68 ?? ?? ?? ?? ff 33 68 ?? ?? ?? ?? ff 33 68 ?? ?? ?? ?? ff 33 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 fc ba 12 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 59 59 5d c3 00 ff ff ff ff 04 00 00 00 68 74 74 70 00 00 00 00 ff ff ff ff 03 00 00 00 3a 2f 2f 00 ff ff ff ff 01 00 00 00 2f 00 00 00 ff ff ff ff 02 00 00 00 64 72 00 00 ff ff ff ff 01 00 00 00 76 00 00 00 ff ff ff ff 02 00 00 00 33 32 00 00 ff ff ff ff 01 00 00 00 2e 00 00 00 ff ff ff ff 04 00 00 00 64 61 74 61 00 00 00 00 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

