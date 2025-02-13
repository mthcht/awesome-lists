rule Trojan_Win32_Tondirt_A_2147658307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tondirt.A"
        threat_id = "2147658307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tondirt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6d 64 2e 65 78 65 20 2f 43 20 72 65 6d 6f 76 65 72 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 4e 6f 20 41 56 20 64 65 74 65 63 74 65 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 70 25 30 35 64 2e 70 6c 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

