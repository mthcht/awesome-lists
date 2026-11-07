rule Trojan_Win32_PapRAT_A_2147981732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PapRAT.A"
        threat_id = "2147981732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PapRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/receive.php" ascii //weight: 1
        $x_1_2 = "/send.php" ascii //weight: 1
        $x_1_3 = {44 45 4c 00 52 55 4e 00 73 74 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {66 61 69 6c 65 64 [0-8] 47 44 52}  //weight: 1, accuracy: Low
        $x_1_5 = {46 44 44 00 [0-16] 55 50 50}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 0f 8a 00 34 50 88 04 11 42 3b 56 10 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

