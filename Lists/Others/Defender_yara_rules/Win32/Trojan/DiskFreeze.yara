rule Trojan_Win32_DiskFreeze_A_2147689691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiskFreeze.A!sys"
        threat_id = "2147689691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiskFreeze"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 8c a2 00 00 00 83 45 ec 01 83 55 f0 00 33 c0 39 45 f0 72 d3 77 08 8b 45 08 39 45 ec 72 c9}  //weight: 1, accuracy: High
        $x_1_2 = {81 7f 0c 20 00 07 00 0f 85 2a 01 00 00 83 7f 04 58 73 0b 83 63 1c 00 be 23 00 00 c0 eb 0f}  //weight: 1, accuracy: High
        $x_1_3 = {21 21 21 21 21 21 21 21 21 21 52 65 61 64 20 4f 72 20 57 72 69 74 65 20 48 44 20 45 72 72 6f 72 20 43 6f 64 65 3d 3d 3d 3d 30 78 25 78 0a}  //weight: 1, accuracy: High
        $x_1_4 = {66 75 63 6b 20 72 65 61 64 20 25 64 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

