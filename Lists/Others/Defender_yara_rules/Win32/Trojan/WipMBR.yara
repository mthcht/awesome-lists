rule Trojan_Win32_WipMBR_B_2147660572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WipMBR.B"
        threat_id = "2147660572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WipMBR"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/s /b /a:-D 2>nul | findstr -i document 2>nul >>" ascii //weight: 1
        $x_1_2 = {66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 8a 44 47 fe 88 44 24 08 2c 30 3c 09 77 ?? 8d 4b ?? 80 f9 09 77 ?? 83 7c 24 0c 09 77 ?? 8d 44 24 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WipMBR_A_2147660604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WipMBR.gen!A"
        threat_id = "2147660604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WipMBR"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d 08 83 f9 02 0f 8c ?? ?? ?? ?? 8b 57 04 0f b7 02 83 e8 30 0f 84}  //weight: 2, accuracy: Low
        $x_1_2 = "/ajax_modal/modal/data.asp" wide //weight: 1
        $x_2_3 = {8b d6 83 e2 03 8a 82 ?? ?? ?? ?? 32 04 0e 6a 00 8d 55 ?? 52 88 45 ?? 6a 01 8d 45 ?? 50 57}  //weight: 2, accuracy: Low
        $x_1_4 = {15 af 52 f0 a0 ff ca 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

