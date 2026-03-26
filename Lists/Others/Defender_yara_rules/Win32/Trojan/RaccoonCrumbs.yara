rule Trojan_Win32_RaccoonCrumbs_2147965598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RaccoonCrumbs!dha"
        threat_id = "2147965598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RaccoonCrumbs"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 38 2e 38 2e 38 2e 38 26 25 70 75 62 6c 69 63 25 [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 31 00 30 00 2e 00 30 00 3b 00 20 00 57 00 69 00 6e 00 36 00 34 00 3b 00 20 00 78 00 36 00 ?? ?? 29 00 20 00 41 00 70 00 70 00 6c 00 65 00 57 00 65 00 62 00 4b 00 69 00 74 00 2f 00 35 00 33 00 37 00 2e 00 33 00 36 00 20 00 28 00 4b 00 48 00 54 00 4d 00 4c 00 2c 00 20 00 6c 00 69 00 6b 00 65 00 20 00 47 00 65 00 63 00 6b 00 6f 00 29 00 20 00 43 00 68 00 72 00 6f 00 6d 00 65 00 2f 00 31 00 32 00 30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 20 00 53 00 61 00 66 00 61 00 72 00 69 00 2f 00 35 00 33 00 37 00 2e 00 33 00 36 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

