rule Trojan_Win32_DynamicOverlord_A_2147814882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DynamicOverlord.A!dha"
        threat_id = "2147814882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DynamicOverlord"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 00 43 00 6f 00 6e 00 66 00 69 00 67 00 20 00 47 00 72 00 6f 00 75 00 70 00 3d 00 22 00 [0-16] 22 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 22 00 [0-32] 22 00 20 00 53 00 74 00 61 00 72 00 74 00 54 00 69 00 6d 00 65 00 3d 00 22 00 30 00 22 00 20 00 45 00 6e 00 64 00 54 00 69 00 6d 00 65 00 3d 00 22 00 32 00 34 00 22 00 20 00 57 00 65 00 65 00 6b 00 44 00 61 00 79 00 73 00 3d 00 22 00 30 00 2c 00 31 00 2c 00 32 00 2c 00 33 00 2c 00 34 00 2c 00 35 00 2c 00 36 00 22 00 3e 00 0a 00 20 00 20 00 20 00 20 00 3c 00 [0-8] 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 6f 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

