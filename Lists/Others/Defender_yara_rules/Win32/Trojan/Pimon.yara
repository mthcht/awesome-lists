rule Trojan_Win32_Pimon_A_2147665949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pimon.A"
        threat_id = "2147665949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pimon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f b6 08 8b 85 58 ff ff ff 8b 55 cc 66 33 0c 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 88 18 c7 45 fc 25 00 00 00 e9 8b fd ff ff c7 45 fc 26 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f b6 0c 08 8b 95 50 ff ff ff 8b 45 cc 66 33 0c 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 88 04 0a c7 45 fc 25 00 00 00 e9 9a fc ff ff c7 45 fc 26 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\3MonIP_original\\itc_original\\explorer.bck" wide //weight: 1
        $x_1_4 = "RegSvr32.exe /s " wide //weight: 1
        $x_1_5 = {5c 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 20 00 48 00 65 00 6c 00 70 00 65 00 72 00 20 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 5c 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {62 00 6b 00 5f 00 61 00 6e 00 30 00 30 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

