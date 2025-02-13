rule Virus_Win32_Miniparg_A_2147600238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Miniparg.A"
        threat_id = "2147600238"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Miniparg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 44 24 40 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 f8 ff 89 44 24 08 0f 84 ?? ?? 00 00 53 55 8b 2d ?? ?? ?? ?? 56 57 6a 00 68 80 00 00 00 6a 03 6a 00 6a 03 8d 8c 24 90 00 00 00 68 00 00 00 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {f3 ab 66 ab 6a 00 52 8d 44 24 3c 6a 1a 50 56 ff 15 ?? ?? ?? ?? 8d 4c 24 34 68 ?? ?? ?? ?? 51 e8 ?? ?? 00 00 83 c4 08}  //weight: 1, accuracy: Low
        $x_1_3 = {51 8d 54 24 2c 68 ?? ?? ?? ?? 52 e8 ?? ?? 00 00 83 c4 20 8d 44 24 14 6a 00 68 82 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

