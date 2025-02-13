rule Spammer_Win32_Wanameil_2147716327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Wanameil"
        threat_id = "2147716327"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Wanameil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 48 3c 8b 4c 01 28 03 c8 74 11 6a 00 ff 75 08 50 ff d1 eb 07 33 c0 40 c3}  //weight: 10, accuracy: High
        $x_10_2 = {50 49 50 45 4c 49 4e 49 4e 47 00 00 43 4f 4e 54 45 4e 54 00 4f 50 45 4e 20 5b}  //weight: 10, accuracy: High
        $x_10_3 = {2e 3f 41 56 78 6d 6d 6d 63 78 6d 6d 6a 63 64 67 40 40 00}  //weight: 10, accuracy: High
        $x_10_4 = {52 43 50 54 20 54 4f 3a 3c 00 00 00 4d 41 49 4c 20 46 52 4f 4d 3a 3c 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

