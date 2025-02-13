rule Backdoor_Win32_Pavica_B_2147688862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pavica.B!dll"
        threat_id = "2147688862"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pavica"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 0f b6 07 50 e8 06 00 00 00 25 32 2e 32 78 00 56 ff 15 ?? ?? ?? ?? 83 c4 0c 47 83 c6 02 59 41 83 f9 10 75 db}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 0c e8 0c 00 00 00 73 7a 61 64 6d 69 6e 68 6f 73 74 00 ff 75 08 e8 ?? ?? ?? ?? 85 c0 74 [0-21] e8 08 00 00 00 68 74 74 70 3a 2f 2f 00 e8}  //weight: 1, accuracy: Low
        $x_2_3 = {b9 02 00 00 00 58 5a 6a 00 52 50 e8 ?? ?? ff ff e2 f3 eb c3 29 00 83 3d ?? ?? ?? 00 01 0f 84 ?? ?? ff ff e8 ?? fe ff ff 68 ?? ?? 00 07 81 2c 24 ?? ?? 00 07 68 ?? ?? 00 07 52 68 ?? ?? 00 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

