rule Virus_Win32_Espoleo_A_2147598625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Espoleo.A"
        threat_id = "2147598625"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Espoleo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5f 78 03 de 8b fb 8b 5f 20 03 de ba 40 02 00 00 83 c2 01 8b 04 93 03 c6 81 38 4c 6f 61 64 75 ?? 81 78 04 4c 69 62 72 75 ?? 81 78 08 61 72 79 41 75 ?? 8b ca eb ?? eb ?? ba 96 01 00 00 83 c2 01 8b 04 93 03 c6 81 38 47 65 74 50 75 ?? 81 78 04 72 6f 63 41 75 ?? 81 78 08 64 64 72 65 75 ?? 8b c2 eb ?? eb ?? 03 47 10 03 4f 10 83 e8 01 83 e9 01 8b 5f 24 03 de 50 b8 00 00 00 00 66 8b 04 4b}  //weight: 1, accuracy: Low
        $x_1_2 = {68 04 01 00 00 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ff ff ff d0 c7 84 ?? ?? fb ff ff ?? ?? ?? ?? c7 84 ?? ?? fb ff ff ?? ?? ?? ?? c7 84 ?? ?? fb ff ff ?? ?? ?? ?? c7 84 ?? ?? fb ff ff ?? ?? ?? ?? 6a 00 6a 02 6a 02 6a 00 6a 00 68 00 00 00 40 53 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ff ff ff d0 8b f0 83 ec 04 8b cc 6a 00 51 68 00 50 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

