rule Worm_Win32_Sholfuse_A_2147708815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sholfuse.A"
        threat_id = "2147708815"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sholfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 83 f9 41 76 0c 66 83 f9 5a 73 06 83 c1 20 66 89 08 83 c2 01 66 83 7c 54 04 00 8d 44 54 04 75 dc}  //weight: 1, accuracy: High
        $x_1_2 = {50 68 f5 06 00 00 68 ?? ?? ?? ?? 56 c7 44 24 20 00 00 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

