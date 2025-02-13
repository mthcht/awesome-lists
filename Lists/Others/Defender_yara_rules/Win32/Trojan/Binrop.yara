rule Trojan_Win32_Binrop_A_2147706777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Binrop.A"
        threat_id = "2147706777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Binrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 63 6f 6e 74 4e 61 6d 65 3c 70 61 69 72 3e [0-32] 3c 73 65 74 [0-1] 3e 24 62 69 6e 64 4e 61 6d 65 3c 70 61 69 72 3e [0-32] 3c 73 65 74 [0-1] 3e 24 64 65 6c 61 79 53 65 63 73 3c 70 61 69 72 3e [0-2] 3c 73 65 74 [0-1] 3e 24 64 72 6f 70}  //weight: 1, accuracy: Low
        $x_1_2 = {24 00 63 00 6f 00 6e 00 74 00 4e 00 61 00 6d 00 65 00 3c 00 70 00 61 00 69 00 72 00 3e 00 [0-48] 3c 00 73 00 65 00 74 00 [0-2] 3e 00 24 00 62 00 69 00 6e 00 64 00 4e 00 61 00 6d 00 65 00 3c 00 70 00 61 00 69 00 72 00 3e 00 [0-48] 3c 00 73 00 65 00 74 00 [0-2] 3e 00 24 00 64 00 65 00 6c 00 61 00 79 00 53 00 65 00 63 00 73 00 3c 00 70 00 61 00 69 00 72 00 3e 00 [0-4] 3c 00 73 00 65 00 74 00 [0-2] 3e 00 24 00 64 00 72 00 6f 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

