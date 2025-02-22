rule Virus_Win32_Liji_A_2147600119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Liji.A"
        threat_id = "2147600119"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Liji"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 47 65 74 50 0f 85 ?? ?? 00 00 81 78 04 72 6f 63 41 0f 85 ?? ?? 00 00 81 78 08 64 64 72 65 0f 85 ?? ?? 00 00 66 81 78 0c 73 73 75 ?? 8b 47 24 03 c5 0f b7 1c 50}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 04 98 03 c5 a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 55 52 00 00 c7 05 ?? ?? ?? ?? 4c 44 00 00 c7 05 ?? ?? ?? ?? 6f 77 00 00 c7 05 ?? ?? ?? ?? 6e 6c 00 00 c7 05 ?? ?? ?? ?? 6f 61 00 00 c7 05 ?? ?? ?? ?? 64 54 00 00 c7 05 ?? ?? ?? ?? 6f 46 00 00 c7 05 ?? ?? ?? ?? 69 6c 00 00 c7 05 ?? ?? ?? ?? 65 41 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 51 6a 64 52 ff b5 ?? ?? ff ff ff 15 ?? ?? ?? ?? ff b5 ?? ?? ff ff ff 15 ?? ?? ?? ?? 8b 8d ?? ?? ff ff 36 c6 84 29 ?? ?? ff ff 00 8b 8d ?? ?? ff ff 36 81 b4 29 ?? ?? ff ff 90 00 00 00 e2 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

