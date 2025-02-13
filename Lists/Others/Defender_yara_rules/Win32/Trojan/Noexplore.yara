rule Trojan_Win32_Noexplore_A_2147615326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Noexplore.A"
        threat_id = "2147615326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Noexplore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 64 20 2e 2e 0d 0a 63 64 20 57 69 6e 64 6f 77 73 0d 0a 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 0d 0a 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 0d 0a 64 65 6c 20 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {2e 74 6d 70 00 74 6d 70 66 69 6c 65 00 62 61 74 63 68 66 69 6c 65 2e 62 61 74 00 2e 62 61 74 00 2e 00 00 64 65 6c 20 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

