rule Worm_Win32_SnowFlake_A_2147646511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SnowFlake.A"
        threat_id = "2147646511"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SnowFlake"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 69 6d 65 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {d4 cb d0 d0 ca b1 bc e4 3a 25 64 2d 25 64 2d 25 64 20 25 64 3a 25 64 3a 25 64 00}  //weight: 1, accuracy: High
        $x_3_3 = {83 c2 01 89 95 ?? ?? ?? ?? 83 bd ?? ?? ?? ?? 64 7d ?? 8b 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 83 c1 01 89 8d ?? ?? ?? ?? 81 bd ?? ?? ?? ?? 70 17 00 00 75 ?? 8b f4 ff 95 ?? ?? ?? ?? 3b f4 e8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

