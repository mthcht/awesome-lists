rule Trojan_Win32_Eterock_A_2147721540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eterock.A"
        threat_id = "2147721540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eterock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\svchost.exe" wide //weight: 1
        $x_1_2 = "\\installed.fgh" wide //weight: 1
        $x_1_3 = "\\hidden_service\\hostname" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-32] 2e 00 6f 00 6e 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_5 = "Malware SMB Block" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

