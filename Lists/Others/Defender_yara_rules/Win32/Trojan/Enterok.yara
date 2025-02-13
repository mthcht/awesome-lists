rule Trojan_Win32_Enterok_A_2147690427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Enterok.A"
        threat_id = "2147690427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Enterok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 76 2e 64 6c 6c 00 00 61 73 64 73 76 63 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = "restore enter ok..." ascii //weight: 1
        $x_1_3 = {63 6d 64 2e 65 78 65 00 2f 63 20 64 65 6c 20 2f 71 20 25 73}  //weight: 1, accuracy: High
        $x_1_4 = {8b 4d fc 8d 3c 08 8b 55 08 8a 0c 37 3a 0c 16 75 ?? 46 3b f3 72 ?? 3b f3 74 ?? 40 3b 45 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

