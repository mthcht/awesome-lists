rule Ransom_Win32_Grymegat_A_2147662742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Grymegat.A"
        threat_id = "2147662742"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Grymegat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 18 ff 2b c7 2b c3 33 c7 89 45 f4 8d 45 f0 8a 55 f4}  //weight: 1, accuracy: High
        $x_1_2 = {68 22 02 00 00 50 e8 ?? ?? ?? ?? 6a 00 8b 03 8b 40 ?? 50 6a 07 50 e8 ?? ?? ?? ?? 6a 73 e8 ?? ?? ?? ?? 0f bf c0 f7 d8 83 c0 81 83 e8 02}  //weight: 1, accuracy: Low
        $x_1_3 = {68 2c 01 00 00 68 f4 01 00 00 e8 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_4 = {68 89 13 00 00 8d 85 ?? ?? ff ff 50 53 e8 ?? ?? ?? ?? 6a 00 68 89 13 00 00 8d 85 ?? ?? ff ff 50 53 e8}  //weight: 1, accuracy: Low
        $x_1_5 = "&Status=Lock&text=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Grymegat_B_2147666504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Grymegat.B"
        threat_id = "2147666504"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Grymegat"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 69 6d 67 2e 70 68 70 3f 67 69 6d 6d 65 49 6d 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 53 74 61 74 75 73 3d 4c 6f 63 6b 20 48 54 54 50 2f 31 2e 31 00}  //weight: 1, accuracy: High
        $x_1_3 = "reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

