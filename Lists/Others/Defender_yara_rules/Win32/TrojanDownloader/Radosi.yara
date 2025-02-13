rule TrojanDownloader_Win32_Radosi_A_2147691007_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Radosi.A"
        threat_id = "2147691007"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Radosi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 61 62 65 6c 31 78 00 01 01 34 00 4f 20 61 72 71 75 69 76 6f 20 65 73 74 e1 20 64 61 6e 69 66 69 63 61 64 6f 20 65 20 6e e3 6f}  //weight: 1, accuracy: High
        $x_1_2 = {4e 00 61 00 6d 00 65 00 53 00 70 00 61 00 63 00 65 00 [0-6] 69 00 74 00 65 00 6d 00 73 00 [0-6] 43 00 6f 00 70 00 79 00 48 00 65 00 72 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 67 8d 85 fc fa ff ff 50 ff 15 ?? ?? ?? ?? 6a 70 8d 8d dc fa ff ff 51 ff 15 ?? ?? ?? ?? 6a 63}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 5c 8d 95 7c fd ff ff 52 ff 15 ?? ?? ?? ?? 6a 47 8d 85 5c fd ff ff 50 ff 15 ?? ?? ?? ?? 6a 62 8d 8d 3c fd ff ff 51}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 70 8d 85 fc fb ff ff 50 ff 15 ?? ?? ?? ?? 6a 3f 8d 8d dc fb ff ff 51 ff 15 ?? ?? ?? ?? 6a 41 8d 95 bc fb ff ff 52 ff 15 ?? ?? ?? ?? 6a 31 8d 85 9c fb ff ff}  //weight: 1, accuracy: Low
        $x_1_6 = {6a 70 8d 8d ?? fb ff ff 51 ff 15 ?? ?? ?? ?? 6a 3f 8d 95 ?? fb ff ff 52 ff 15 ?? ?? ?? ?? 6a 41 8d 85 ?? fb ff ff 50 ff 15 ?? ?? ?? ?? 6a 31 8d 8d}  //weight: 1, accuracy: Low
        $x_1_7 = {ff d6 8d 55 c4 6a 67 52 ff d6 8d 45 a4 6a 75 50 ff d6 8d 4d 84 6a 61 51 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

