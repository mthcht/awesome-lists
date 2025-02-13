rule Virus_Win32_Virut_2147595183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut"
        threat_id = "2147595183"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 dc 2d 00 01 89 85 e4 fd ff ff e9 f8 2e 01 00 01 8b 4d fc 33 cd e8 c0 fc ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 f7 d2 90 0f 84 7e 44 00 00 ba d1 8e a8 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Virus_Win32_Virut_AA_2147597702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.AA"
        threat_id = "2147597702"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 27 00 00 00 53 b9 bf 0c 00 00 8b da 66 31 10 8d 14 13 86 d6 8d 40 02 e2 f3 5b c3 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {0f 31 c3 b8 00 10 00 00 33 c9 eb 25 85 c0 75 08 cd 2c 85 c0 79 ed eb 0e 66 8c ca c1 e3 0a 78 e3 73 e1 38 fe 74 dd e8 d5 ff ff ff 91 e8 cf ff ff ff f7 d9 55 03 c1 8b 6c 24 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Virut_AI_2147599835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.AI"
        threat_id = "2147599835"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 75 09 cd 2e c1 e0 1f 79 1d}  //weight: 1, accuracy: High
        $x_1_2 = {55 b8 00 40 00 00 2b c9 ff 74 24 04 5d f7 d9 81 6c 24 04 ?? ?? ?? ?? 8d 84 01 80 fe ff ff 81 ed 06 10 30 00 85 c0 79 ae}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Virut_B_2147601110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.gen!B"
        threat_id = "2147601110"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 0c 00 00 00 43 6c 6f 73 65 48 61 6e 64 6c 65 00 53 ff d6 89 85 ?? ?? ?? ?? e8 0d 00 00 00 43 72 65 61 74 65 45 76 65 6e 74 41 00 53 ff d6 89 85 ?? ?? ?? ?? e8 0d 00 00 00 47 65 74 4c 61 73 74 45 72 72 6f 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 ff d6 89 85 ?? ?? ?? ?? e8 ?? ?? 00 00 85 c0 74 21 50 ff 95 ?? ?? ?? ?? 85 c0 75 10 8d 85 ?? ?? ?? ?? 8a 50}  //weight: 1, accuracy: Low
        $x_1_3 = {5d c3 5a 6a 00 6a 00 6a 00 6a 00 68 01 00 04 00 8b c4 6a 00 50 6a 0c 8b c4}  //weight: 1, accuracy: High
        $x_3_4 = {66 81 78 02 74 50 75 09 81 78 05 6f 63 41 64 74 05 e2 ea 59 5d c3 29 0c 24 8b 72 24 59 03 f3 0f b7 04 4e 8b 7a 1c 03 fb 8d 8d ?? ?? ?? ?? 8b 34 87 51 03 f3 53 ff d6}  //weight: 3, accuracy: Low
        $x_1_5 = {55 8b ec e8 ?? 00 00 00 e8 ?? 00 00 00 [0-160] 8b 54 24 10 31 c0 8f 82 b8 00 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Virut_L_2147601321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.gen!L"
        threat_id = "2147601321"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ircd.zief.pl" ascii //weight: 2
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" ascii //weight: 1
        $x_1_3 = "TargetHost" ascii //weight: 1
        $x_1_4 = "JOIN" ascii //weight: 1
        $x_1_5 = "NICK " ascii //weight: 1
        $x_1_6 = "USER " ascii //weight: 1
        $x_1_7 = "O noon of life! O time to celebrate!" ascii //weight: 1
        $x_1_8 = "O summer garden!" ascii //weight: 1
        $x_1_9 = "Relentlessly happy and expectant, standing: -" ascii //weight: 1
        $x_1_10 = "Watching all day and night, for friends I wait:" ascii //weight: 1
        $x_1_11 = "Where are you, friends? Come! It is time! It's late!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Virut_I_2147601323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.gen!I"
        threat_id = "2147601323"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "99"
        strings_accuracy = "Low"
    strings:
        $x_99_1 = {81 e3 00 f0 ff ff [0-64] 81 7b 4e 54 68 69 73 [0-32] 66 81 38 50 45 [0-16] 8b 50 78 03 d3 8b 72 20 8b 4a 18 03 f3 51 ad [0-8] 81 78 ?? [0-40] [0-4] 81 78 ?? [0-40] 74 05 e2 ?? 59 5d c3 29 0c 24 8b 72 24 59 03 f3 0f b7 04 4e 8b 7a 1c 03 fb 8b 34 87 03 f3 e8 0c 00 00 00 43 6c 6f 73 65 48 61 6e 64 6c 65 00 53 ff d6 89 85 ?? ?? ?? ?? e8 0d 00 00 00 43 72 65 61 74 65 45 76 65 6e 74 41 00 53 ff d6 89 85 ?? ?? ?? ?? e8 0d 00 00 00 47 65 74 4c 61 73 74 45 72 72 6f 72 00 53 ff d6 89 85}  //weight: 99, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Virut_AF_2147601324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.gen!AF"
        threat_id = "2147601324"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\W32_Virtu" ascii //weight: 1
        $x_1_2 = {54 61 72 67 65 74 48 6f 73 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "JOIN &virtu" ascii //weight: 1
        $x_1_4 = {81 4a 24 60 00 00 e0}  //weight: 1, accuracy: High
        $x_1_5 = {c7 43 08 20 20 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Virut_AI_2147601325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.gen!AI"
        threat_id = "2147601325"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 45 58 45 00 74 ?? 3d 53 43 52 00 0f ?? ?? ff ff ff 8b 03 3d 57 49 4e 43 0f ?? ?? ff ff ff 3d 57 43 55 4e 0f ?? ?? ff ff ff 3d 57 43 33 32 0f ?? ?? ff ff ff 3d 50 53 54 4f 0f ?? ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {66 81 3e 4d 5a 0f 85 ?? ?? 00 00 8b 5e 3c 03 de 66 81 3b 50 45 0f 85 ?? ?? 00 00 f7 43 16 00 20 00 00 0f 85 ?? ?? 00 00 f6 43 5c 02 0f 84 ?? ?? 00 00 81 7e 20 20 20 20 20 0f 84 ?? ?? 00 00 e8 ?? ?? ff ff 0f 82 ?? ?? 00 00 8b 42 08 8b 4a 10}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 10 00 2a 00 75 ?? 66 81 7c 24 0c 6c 71 75 ?? 60 e8 ?? ?? ff ff 75 ?? e8 ?? ?? ff ff e8 ?? ?? ff ff 61 2e ff 2d 78 56 34 12 b8 ?? ?? ?? ?? 60 e8 ?? ?? ff ff 75 ?? 8b 44 24 30 8d b5 ?? ?? ?? ?? 8b 50 08 66 81 3a 06 02 73 ?? 56 68 00 00 ff 00 8b c4 6a 00 52 50 ff 95 ?? ?? ?? ?? 83 c4 08 81 3e 5c 3f 3f 5c 75 03}  //weight: 1, accuracy: Low
        $x_1_4 = {81 3e 50 52 49 56 0f 85 ?? ?? 00 00 83 c6 08 ac 3c 0d 0f 84 ?? ?? 00 00 3c 20 75 ?? ac 3c 3a 0f 85 ?? ?? 00 00 ad 0d 20 20 20 20 3d 21 67 65 74 75 ?? ac 3c 20 75 ?? 81 7e ff 20 68 74 74 75 ?? 81 7e 03 70 3a 2f 2f 75 ?? c6 47 ff 00 0f 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Virus_Win32_Virut_C_2147603101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.gen!C"
        threat_id = "2147603101"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 33 34 74 33 58 76 33 6e 74 41 00 43 6c 30 73 33 48 34 6e 64 6c 33 00}  //weight: 1, accuracy: High
        $x_1_2 = {56 78 5f 34 00}  //weight: 1, accuracy: High
        $x_1_3 = {ad 03 c3 66 81 78 02 74 50 75 09 81 78 05 6f 63 41 64 74 05 e2 ea 59 5d c3}  //weight: 1, accuracy: High
        $x_1_4 = {81 7b 4e 54 68 69 73 [0-128] 74 0e [0-128] 03 43 3c [0-128] 66 81 38 50 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Virus_Win32_Virut_AQ_2147605035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.AQ"
        threat_id = "2147605035"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc e8 29 00 00 00 53 b9 a0 0d 00 00 8b da 66 31 10 40 86 d6 40 8d 14 13 e2 f4 5b c3 ?? ?? 5d c3 0f 31 ff 24 24 55 b8 00 80 00 00 33 c9 eb 19 85 c0 75 06 cd 2e 85 c0 79 ec 55 e8 e1 ff ff ff 91 e8 db ff ff ff 83 c4 08 8b 54 24 04 2b c1 87 ea 81 6c 24 04 ?? ?? ?? ?? 2d 80 01 00 00 73 bf 81 ed 06 10 30 00 8d 85 77 10 30 00 66 8b 90 a5 ff ff ff e8 8f ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Virut_D_2147605771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.gen!D"
        threat_id = "2147605771"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {cd 2e 85 c0 79 ec 55 e8 e1 ff ff ff 91 e8 db ff ff ff 83 c4 08 8b 54 24 04 2b c1 87 ea 81 6c 24 04 ?? ?? ?? 00 2d 80 01 00 00 73 bf 81 ed ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 66 8b 90 ?? ff ff ff e8 8f ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {cd 2d eb 05 c1 e3 09 79 ef e8 eb ff ff ff 8b c8 e8 e4 ff ff ff f7 d9 55 8b 6c 24 04 03 c1 81 6c 24 04 ?? ?? ?? 00 2d 00 01 00 00 73 cb 81 ed ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 8a 90 ?? ff ff ff e8 a3 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {cd 2e 85 c0 79 ec 55 e8 e1 ff ff ff 91 e8 db ff ff ff 83 c4 08 8b 54 24 04 2b c1 87 ea 81 6c 24 04 ?? ?? ?? 00 2d 80 01 00 00 cc bf ?? ?? ?? ?? 30 00 8d 85 ?? ?? ?? ?? 66 8b 90 ?? ff ff ff e8 8f ff ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {e8 27 00 00 00 81 c7 ?? ?? ?? ?? 29 d2 81 ca ?? ?? 00 00 bd ?? 00 00 00 57 8a 07 66 29 e8 86 07 83 c7 01 4a 83 fa 00 75 f0 5f ff e7 5f ff e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Virus_Win32_Virut_AT_2147614201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.AT"
        threat_id = "2147614201"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {cd 2e c1 e0 1f 79 18}  //weight: 1, accuracy: High
        $x_1_2 = {55 b8 00 40 00 00 2b c9 87 6c 24 04 f7 d1 89 6c 24 04 81 6c 24 04 ?? ?? ?? ?? 8d 84 01 b3 fe ff ff 90 85 c0 79 9f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Virut_M_2147623619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.gen!M"
        threat_id = "2147623619"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {3c 69 66 72 61 6d 65 [0-16] 73 72 63 3d [0-5] 68 74 74 70 3a 2f 2f [0-32] 2f 72 63 2f [0-32] 3c 2f 69 66 72 61 6d 65 3e}  //weight: 4, accuracy: Low
        $x_4_2 = {68 14 50 bd c3 8f 46 1c}  //weight: 4, accuracy: High
        $x_1_3 = {81 3e 50 49 4e 47 75}  //weight: 1, accuracy: High
        $x_1_4 = {81 3e 50 52 49 56 0f 85}  //weight: 1, accuracy: High
        $x_1_5 = {3d 45 58 45 00 74 ?? 3d 53 43 52 00 74}  //weight: 1, accuracy: Low
        $x_2_6 = {3d 48 54 4d 00 74 ?? 3d 50 48 50 00 74 ?? 3d 41 53 50 00}  //weight: 2, accuracy: Low
        $x_2_7 = {0d 20 20 20 20 3d 21 67 65 74 0f 85}  //weight: 2, accuracy: High
        $x_1_8 = {81 7e ff 20 68 74 74 0f 85 ?? ?? ?? ?? 81 7e 03 70 3a 2f 2f 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Virut_HNC_2147925661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.HNC!MTB"
        threat_id = "2147925661"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {77 62 00 00 72 62 00 00 5c 74 65 6d 70 32 2e 65 78 65 00 00 00 00 00 00 5c 74 65 6d 70 31 2e 65 78 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {8b 74 24 18 8b 44 24 14 d1 e8 46 89 44 24 14 83 fe 1a 89 74 24 18}  //weight: 1, accuracy: High
        $x_1_3 = {f3 a4 eb 06 c7 06 00 00 00 00 8b 54 24 1c 8b 44 24 18 8b 74 24 10 33 c9 66 8b 4a 04 40 83 c6 0e 3b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Virut_HNE_2147929003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Virut.HNE!MTB"
        threat_id = "2147929003"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a2 b0 80 f2 cf dc 71 ce 2b 86 68 8f ac 33 78 aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

