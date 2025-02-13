rule Trojan_Win32_Wirond_A_2147718365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wirond.A"
        threat_id = "2147718365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wirond"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 24 53 00 65 00 c7 44 24 28 72 00 76 00 c7 44 24 2c 69 00 63 00 c7 44 24 30 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 14 53 00 52 00 c7 44 24 18 41 00 41 00 c7 44 24 1c 31 00 00 00 ff d0}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 e0 77 00 69 00 c7 45 e4 6e 00 77 00 c7 45 e8 6f 00 72 00 c7 45 ec 64 00 30 00 c7 45 f0 31 00 36 00}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 e0 6f 00 72 00 c7 45 e4 64 00 30 00 c7 45 e8 31 00 36 00 c7 45 ec 2e 00 65 00 c7 45 f0 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

