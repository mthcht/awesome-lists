rule Virus_Win32_Tufik_G_2147601131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Tufik.G"
        threat_id = "2147601131"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Tufik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {55 8b ec 83 c4 fc 60 c7 45 fc 00 00 00 00 e8 00 00 00 00 5b 81 eb ?? 16 40 00 55 8d 83 ?? 17 40 00 50 8d 83 ?? 16 40 00 50 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 8b 7d 08 81 e7 00 00 ff ff 66 81 3f 4d 5a 75 11 8b f7 03 76 3c 66 81 3e 50 45 75 05 89 7d fc eb 10}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Tufik_A_2147602395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Tufik.gen!A"
        threat_id = "2147602395"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Tufik"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 67 43 6c 6f 73 65 4b 65 79 00 4d 6f 76 65 46 69 6c 65 41 00 6c 73 74 72 63 70 79 00 47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 00 6c 73 74 72 63 61 74 00 6c 73 61 73 73 00 61 6c 67 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 fc 00 00 00 00 e8 00 00 00 00 5b 81 eb ?? ?? ?? ?? 55 8d 83 ?? ?? ?? ?? 50 8d 83 ?? ?? ?? ?? 50 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 8b 7d 08 81 e7 00 00 ff ff 66 81 3f 4d 5a 75 11 8b f7 03 76 3c 66 81 3e 50 45 75 05 89 7d fc eb 10 81 ef 00 00 01 00 81 ff 00 00 00 70 72 02 eb d8 64 8f 05 00 00 00 00 83 c4 0c 61 8b 45 fc}  //weight: 1, accuracy: Low
        $x_1_3 = {50 6a 00 6a 00 8d 83 ?? ?? ?? ?? 50 6a 00 6a 00 ff 93 ?? ?? ?? ?? 50 ff 93 ?? ?? ?? ?? 6a 64 ff 93 ?? ?? ?? ?? e9 ?? ?? 00 00 55 8b ec 53 56 57 e8 00 00 00 00 5b 81 eb ?? ?? ?? ?? b8 04 01 00 00 50}  //weight: 1, accuracy: Low
        $x_1_4 = {50 68 06 00 02 00 6a 00 8d 83 ?? ?? ?? ?? 50 68 02 00 00 80 ff 93 ?? ?? ?? ?? 6a 50 8d 83 ?? ?? ?? ?? 50 6a 01 6a 00 8d 83 ?? ?? ?? ?? 50 ff b3 ?? ?? ?? ?? ff 93 ?? ?? ?? ?? ff b3 ?? ?? ?? ?? ff 93 ?? ?? ?? ?? 6a 00 6a 00 6a 00 8d 83 ?? ?? ?? ?? 50 6a 00 6a 00 ff 93 ?? ?? ?? ?? 5f 5e 5b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

