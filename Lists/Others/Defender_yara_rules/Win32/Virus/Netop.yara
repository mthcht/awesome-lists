rule Virus_Win32_Netop_A_2147599954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Netop.A"
        threat_id = "2147599954"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Netop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c3 2c 8b fb 33 c0 47 38 07 ?? ?? 8b 47 fc 0d 20 20 20 20 3d 2e 65 78 65 ?? ?? 3d 2e 73 63 72}  //weight: 1, accuracy: Low
        $x_1_2 = {96 66 81 3e 4d 5a 0f 85 ?? ?? 00 00 03 76 3c 66 81 3e 50 45 0f 85 ?? ?? ?? ?? 81 7e 08 6b 72 61 64}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 46 24 20 00 00 e0 8b 85 ?? ?? ?? ?? 8b 58 28 89 9d ?? ?? ?? ?? 8b 9d ?? ?? ?? ?? 89 58 28 8b 5e 0c 03 5e 08 89 58 50 c7 40 08 6b 72 61 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

