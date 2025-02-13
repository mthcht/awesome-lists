rule Ransom_Win64_Jabaxsta_A_2147728734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Jabaxsta.A"
        threat_id = "2147728734"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Jabaxsta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {45 8d 4a 02 b8 c1 87 ff e0 41 f7 e2 41 8b c2 45 ?? ?? ?? 2b c2 4d ?? ?? ?? d1 e8 03 c2 41 8b d2 c1 e8 0c 69 c0 08 11 00 00 2b d0 48 63 c2 0f ?? ?? ?? ?? ?? ?? ?? 41 30 43 fa b8 c1 87 ff e0 41 f7 e0 44 2b c2 41 d1 e8 44 03 c2 41 8b d2 41 c1 e8 0c 41 69 c0 08 11 00 00 45 ?? ?? ?? 2b d0}  //weight: 20, accuracy: Low
        $x_20_2 = {5c 00 75 00 c7 ?? ?? ?? 73 00 65 00 c7 ?? ?? ?? 72 00 73 00 c7 ?? ?? ?? 5c 00 50 00 c7 ?? ?? ?? 75 00 62 00 c7 ?? ?? ?? 6c 00 69 00 c7 ?? ?? ?? 63 00 5c 00 c7 ?? ?? ?? 77 00 69 00 c7 ?? ?? ?? 6e 00 64 00 c7 ?? ?? ?? 6f 00 77 00 c7 ?? ?? ?? 2e 00 62 00 c7 ?? ?? ?? 61 00 74 00}  //weight: 20, accuracy: Low
        $x_20_3 = {b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 d0 8d 04 92 03 c0 2b c8 83 f9 09 7e ?? 83 c1 57 eb ?? 83 c1 30}  //weight: 20, accuracy: Low
        $x_20_4 = "Projects From Ryuk" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win64_Jabaxsta_B_2147730123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Jabaxsta.B!bit"
        threat_id = "2147730123"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Jabaxsta"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b d6 45 84 c0 74 0e 49 8b c7 ff c2 48 8d 40 01 44 38 28 75 f5 44 3b d2 7d 0b 41 30 09 41 ff c2 49 ff c1 eb d2}  //weight: 1, accuracy: High
        $x_1_2 = {41 8b c2 41 ff c2 99 f7 f9 48 63 c2 42 0f b6 04 20 41 30 01 49 ff c1 45 3b d3 72 c9}  //weight: 1, accuracy: High
        $x_1_3 = "efkrm4tgkl4ytg4" ascii //weight: 1
        $x_1_4 = "UNIQUE_ID_DO_NOT_REMOVE" wide //weight: 1
        $x_1_5 = "RyukReadMe.txt" wide //weight: 1
        $x_1_6 = {63 00 73 00 72 00 73 00 73 00 2e 00 65 00 78 00 65 00 [0-16] 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 [0-16] 6c 00 73 00 61 00 61 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

