rule Virus_Win32_Grum_B_2147583437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Grum.B"
        threat_id = "2147583437"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Grum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 5b 81 eb ?? ?? ?? ?? c3 64 a1 30 00 00 00 85 c0 78 0c 8b 40 0c 8b 70 1c ad 8b 40 08 eb 09 8b 40 34 8b 80 b8 00 00 00 c3 55 8b ec 55 53 56 57 8b 7d 0c 8b f7 8b 6d 08 8b 55 3c 8b 54 2a 78 8d 5c 2a 1c ff 73 04 01 2c 24 33 c9 49 ff 34 24 87 34 24 33 d2 ad 03 c5 c1 c2 03 32 10 40 80 38 00 75 f5 41 87 34 24 39 16 75 e5 8b 43 08 03 c5 0f b7 04 48 c1 e0 02 03 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Grum_C_2147593662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Grum.C"
        threat_id = "2147593662"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Grum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {60 e8 00 00 00 00 5d 81 ed 12 25 9c 00 33 c9 33 c0 33 db 99 ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad e9 01 01 00 00 ac fe c4 d1 e8 8a 84 05 4f 26 9c 00 72 03 c1 e8 04 83 e0 0f 93 80 fb 0e 0f 84 f2 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Grum_G_2147595127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Grum.G"
        threat_id = "2147595127"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Grum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 40 00 00 6a 00 ff 73 ?? 6a ff ff 93 ?? ?? 00 00 8b 73 ?? 0b f6 74 56 03 73 ?? 8b 7e 10 03 7b ?? 8b 4e 0c 0b c9 74 46 03 4b ?? 6a 00 6a 00 51 ff 93 ?? ?? 00 00 8b c8 56 8b 06 0b c0 75 03 8b 46 10 8b f0 03 73 ?? ad 0b c0 74 1c 79 07 25 ff ff ff 7f eb 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

