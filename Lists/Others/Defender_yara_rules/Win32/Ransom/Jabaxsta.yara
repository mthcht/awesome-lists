rule Ransom_Win32_Jabaxsta_A_2147728857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Jabaxsta.A"
        threat_id = "2147728857"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Jabaxsta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {b8 89 d3 51 27 8b ce f7 e6 c1 ea 0a 69 c2 0b 1a 00 00 2b c8 0f b6 81 ?? ?? ?? ?? 8d 8f ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 03 ce b8 89 d3 51 27 f7 e1 8b ce c1 ea 0a 69 c2 0b 1a 00 00 2b c8}  //weight: 20, accuracy: Low
        $x_20_2 = {5c 00 75 00 c7 ?? ?? 73 00 65 00 ?? ?? ?? c7 ?? ?? 72 00 73 00 c7 ?? ?? 5c 00 50 00 c7 ?? ?? 75 00 62 00 c7 ?? ?? 6c 00 69 00 c7 ?? ?? 63 00 5c 00 c7 ?? ?? 77 00 69 00 c7 ?? ?? 6e 00 64 00 c7 ?? ?? 6f 00 77 00 c7 ?? ?? 2e 00 62 00 c7 ?? ?? 61 00 74 00}  //weight: 20, accuracy: Low
        $x_10_3 = "vssadmin Delete Shadows /all /quiet" ascii //weight: 10
        $x_10_4 = {76 73 73 61 64 6d 69 6e 20 72 65 73 69 7a 65 20 73 68 61 64 6f 77 73 74 6f 72 61 67 65 20 2f 66 6f 72 3d ?? 3a 20 2f 6f 6e 3d ?? 3a 20 2f 6d 61 78 73 69 7a 65 3d}  //weight: 10, accuracy: Low
        $x_10_5 = {64 65 6c 20 2f 73 20 2f 66 20 2f 71 20 ?? 3a 5c 2a 2e 56 48 44 20 ?? 3a 5c 2a 2e 62 61 63 20 ?? 3a 5c 2a 2e 62 61 6b 20 ?? 3a 5c 2a 2e 77 62 63 61 74 20 ?? 3a 5c 2a 2e 62 6b 66 20 ?? 3a 5c 42 61 63 6b 75 70 2a 2e 2a 20 ?? 3a 5c 62 61 63 6b 75 70 2a 2e 2a 20 ?? 3a 5c 2a 2e 73 65 74 20 ?? 3a 5c 2a 2e 77 69 6e 20 ?? 3a 5c 2a 2e 64 73 6b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Jabaxsta_C_2147730121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Jabaxsta.C!bit"
        threat_id = "2147730121"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Jabaxsta"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 83 c1 01 89 4d f4 8b 55 f4 3b 15 ?? ?? ?? 00 7d 26 8b 45 f4 0f b6 88 ?? ?? ?? 00 8b 45 f4 33 d2 f7 75 ec 0f be 92 ?? ?? ?? 00 33 ca 8b 45 f4 88 88 ?? ?? ?? 00 eb c6}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f8 83 c2 01 89 55 f8 8b 45 f8 3b 05 ?? ?? ?? 00 7d 26 8b 4d f8 0f b6 89 ?? ?? ?? 00 8b 45 f8 33 d2 f7 75 ec 0f be 92 ?? ?? ?? 00 33 ca 8b 45 f8 88 88 ?? ?? ?? 00 eb c6}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 01 00 00 00 85 c0 74 25 ff 15 ?? ?? ?? 00 33 d2 b9 19 00 00 00 f7 f1 83 c2 41 89 55 ?? 8b 55 f4 66 8b 45 ?? 66 89 44 55 ?? eb 02 eb d2}  //weight: 1, accuracy: Low
        $x_1_4 = {72 51 4a 62 47 44 44 77 77 46 47 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Jabaxsta_D_2147730122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Jabaxsta.D!bit"
        threat_id = "2147730122"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Jabaxsta"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 f7 ff 85 d2 75 01 46 8b c1 99 f7 fb 8a 82 ?? ?? ?? ?? 32 06 46 88 81 ?? ?? ?? ?? 8b c1 41 81 f9 ?? ?? 00 00 72 d7}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 99 f7 fe 8a 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 83 f9 ?? 7c dc}  //weight: 1, accuracy: Low
        $x_1_3 = "efkrm4tgkl4ytg4" ascii //weight: 1
        $x_1_4 = {42 54 43 20 77 61 6c 6c 65 74 3a 00 52 79 75 6b}  //weight: 1, accuracy: High
        $x_1_5 = "UNIQUE_ID_DO_NOT_REMOVE" wide //weight: 1
        $x_1_6 = "RyukReadMe.txt" wide //weight: 1
        $x_1_7 = {63 00 73 00 72 00 73 00 73 00 2e 00 65 00 78 00 65 00 [0-16] 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 [0-16] 6c 00 73 00 61 00 61 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_8 = "tapSrZdjfNvFMdmZyoPfOLSRQUpulnwuWWgWovDwAgFZCAanopzefqETZVUaBFJvhkLWBxBpKXAvaZasPkQAcIvuidpEwb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

