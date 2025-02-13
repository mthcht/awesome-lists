rule Trojan_Win32_Crysche_A_2147607556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crysche.A"
        threat_id = "2147607556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysche"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Critical System Check" ascii //weight: 1
        $x_1_2 = "\\esche.tmp" ascii //weight: 1
        $x_1_3 = "/mcash/" ascii //weight: 1
        $x_1_4 = "check.php?mac=" ascii //weight: 1
        $x_1_5 = {2a d5 8b 14 ab a2 ce 11 b1 1f 00 aa 00 53 05 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

