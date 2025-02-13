rule Trojan_Win32_PricklyPear_A_2147894766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PricklyPear.A!dha"
        threat_id = "2147894766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PricklyPear"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {30 1a 8a 02 3c 4d 74 0b 32 c3 88 02 80 c3 01 75 ef eb 06 8a c3 34 4d 88 02 33 f6 39 75 0c 76 12 8a 0c 16 8a c1 32 c3 8a d9 88 04 16 46 3b 75 0c 72 ee}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

