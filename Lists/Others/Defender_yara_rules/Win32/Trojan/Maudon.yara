rule Trojan_Win32_Maudon_A_2147734730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Maudon.A"
        threat_id = "2147734730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Maudon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 31 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 2e 41 64 64 46 72 6f 6d 53 74 72 69 6e 67 28 24 78 29 3b 24 6e 6e 20 3d 20 24 77 2e 4e 61 6d 65 3b 24 65 2e 52 75 6e 28 28 24 6e 6e 20 2b 20 27 21 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 65 27 29 29 3b 00 77}  //weight: 1, accuracy: High
        $x_1_2 = {5c 74 65 6d 70 5c 61 2e 70 73 31 00 63 6d 64 2e 65 78 65 00 6f 70 65 6e 00 00 00 00 00 00 00 00 2f 43 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 73 68 65 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

