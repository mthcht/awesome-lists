rule Trojan_Win32_Trickbot_A_2147719709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.A"
        threat_id = "2147719709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ghost" wide //weight: 1
        $x_1_2 = "Eye Demon" wide //weight: 1
        $x_1_3 = "Red Killa" wide //weight: 1
        $x_1_4 = "Scorpion" wide //weight: 1
        $x_1_5 = "Legend.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_2147723014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot"
        threat_id = "2147723014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 0c 8b 4c 24 04 85 d2 74 47 33 c0 8a 44 24 08 57 8b f9 83 fa 04 72 2d f7 d9 83 e1 03 74 08 2b d1 88 07 47 49 75 fa 8b c8 c1 e0 08 03 c1 8b c8 c1 e0 10 03 c1 8b ca 83 e2 03 c1 e9 02 74 06 f3 ab 85 d2 74 06 88 07 47 4a 75 fa 8b 44 24 08 5f c3}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 8b 45 0c 81 ec 6c ?? 00 00 56 8b 75 08 57 3d 11 01 00 00 0f 87 e6 01 00 00 0f 84 7a 01 00 00 8b c8 49 74 3e 49 74 29 83 e9 0d 0f 85 ec 01 00 00 8d 45 94 50 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_N_2147727583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.N"
        threat_id = "2147727583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\ExploitDb\\" ascii //weight: 1
        $x_1_2 = {73 68 65 6c 6c 63 6f 64 65 5f 6d 61 69 6e 90}  //weight: 1, accuracy: High
        $x_1_3 = "TnRVbm1hcFZpZXdPZlNlY3Rpb24=" ascii //weight: 1
        $x_1_4 = "hukmnjufewgjoghuigohvbtysoghgty" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Trickbot_O_2147728174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.O"
        threat_id = "2147728174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 00 53 00 79 00 73 00 74 00 65 00 6d 00 44 00 72 00 69 00 76 00 65 00 25 00 5c 00 [0-10] 73 00 76 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 [0-10] 73 00 76 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "toler.png" wide //weight: 1
        $x_1_4 = {25 00 73 00 5c 00 43 00 24 00 5c 00 [0-10] 73 00 76 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {25 00 73 00 5c 00 41 00 44 00 4d 00 49 00 4e 00 24 00 5c 00 [0-10] 73 00 76 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PA_2147730788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PA"
        threat_id = "2147730788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e0 02 01 d0 c1 e0 03 03 45 d4 8b 40 0c 89 c2 03 55 dc 8b 45 cc 89 cb 89 d7 89 de 89 c1 f3 a4 66 ff 45 e6 66 8b 45 e6 66 3b 45 da 0f 92 c0 84 c0 75 97 8b 45 e0 83 e8 80 89 45 c8 8b 45 e0 8b 50 28 8b 45 dc 01 d0 89 45 c4 8b 45 c4 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_Z_2147730878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.Z"
        threat_id = "2147730878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/getq/" ascii //weight: 1
        $x_2_2 = {6a 5c 89 3e e8 76 02 00 00 8a d0 57 6a 47 88 55 ff 88 56 04 e8 66 02 00 00 57 6a 6f 88 46 05 e8 5b 02 00 00 8a f0 57 88 76 06 6a 67 88 76 07 e8 4b 02 00 00 57 6a 6c 88 46 08 e8 40 02 00 00 57 8a e8 6a 65}  //weight: 2, accuracy: High
        $x_2_3 = {6a 44 e8 4c 01 00 00 6a 50 88 01 e8 43 01 00 00 6a 53 88 41 01 e8 39 01 00 00 6a 54}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_V_2147733313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.V"
        threat_id = "2147733313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rrljjeiidllgttn}}wyysooihhchhcnni{zu" ascii //weight: 1
        $x_1_2 = "xkliffgbghcjkfqqk" ascii //weight: 1
        $x_1_3 = "zrrliided_cb]cb]cb]cb]cb]dc" ascii //weight: 1
        $x_1_4 = "%Ay%Ay%Ay%Ay%Ay%By*Ay%Ay%Ay%Ay%Ay%Bw+PRKVVQgfaz" ascii //weight: 1
        $x_4_5 = {75 39 2d 63 2a 4a 6e 54 2b 69 58 42 78 73 50 00 7a 6b 6d 73 39 4f 44 64 75 21 76 76 4d 35 54 51 34 44 78 45 00 46 67 78 71 77 61 4b 4c 6f 2e 7a 6f 70}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_W_2147733314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.W"
        threat_id = "2147733314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Eld.23lenreK" ascii //weight: 1
        $x_1_2 = "AtxetnoCeriuqcAtpyrC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AA_2147733914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AA"
        threat_id = "2147733914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 55 73 65 72 73 5c 55 73 65 72 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 30 38 5c 50 72 6f 6a 65 63 74 73 5c 53 74 75 70 69 64 20 57 69 6e 64 69 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 52 65 6c 65 61 73 65 5c [0-32] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PB_2147734504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PB!MTB"
        threat_id = "2147734504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Tr9jnXy5R#K{qzk" ascii //weight: 1
        $x_1_2 = "duz$E#kQ%etIq0F*9UNvHfFrMQ" ascii //weight: 1
        $x_1_3 = {8a 00 88 c1 8b 45 ?? 8b 9c ?? ?? ?? ?? ?? 8b 45 ?? 8b 84 ?? ?? ?? ?? ?? 01 d8 25 ff 00 00 80 85 c0 79 ?? 48 0d 00 ff ff ff 40 8b 84 ?? ?? ?? ?? ?? 31 c8 88 02 ff 45 ?? 8b 45 ?? 3b 45 ?? 0f 92 c0 84 c0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Trickbot_PB_2147734504_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PB!MTB"
        threat_id = "2147734504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 c7 45 ?? 00 00 00 00 eb ?? 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 3b 4d ?? 74 ?? 8b 45 ?? 33 d2 b9 ?? ?? ?? ?? f7 f1 8b 45 ?? 03 45 ?? 8b 4d ?? 8a 00 32 04 11 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-64] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_SD_2147735574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SD!MTB"
        threat_id = "2147735574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 8b 55 0c 8d 1c 02 8b 45 e4 8b 55 0c 01 d0 0f b6 00 89 c6 8b 45 08 89 04 24 e8 ?? ?? ?? ?? 89 c7 8b 45 e4 ba 00 00 00 00 f7 f7 89 d1 89 ca 8b 45 08 01 d0 0f b6 00 31 f0 88 03 83 45 e4 01 8b 45 e4 3b 45 10 75}  //weight: 1, accuracy: Low
        $x_1_2 = {89 14 24 ff d0 8b 45 c4 c7 04 24 ?? ?? ?? ?? ff d0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_SX_2147739687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SX!MTB"
        threat_id = "2147739687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 8b 4d 00 8b fb 8b 51 0c 8b 59 14 2b d3 03 d6 66 0f b6 0a 8b d9 2b cf 66 85 c9 7d ?? 81 c1 00 01 00 00 46 88 0a 3b f0 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_SX_2147739687_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SX!MTB"
        threat_id = "2147739687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 8b 55 0c 8d 1c 02 8b 45 f4 8b 55 0c 01 d0 8a 00 89 c6 8b 45 08 89 04 24 e8 ?? ?? ?? ?? 89 45 e4 8b 45 f4 ba 00 00 00 00 f7 75 e4 89 d1 89 ca 8b 45 08 01 d0 8a 00 31 f0 88 03 ff 45 f4 8b 45 f4 3b 45 10 0f 95 c0 84 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_A_2147739743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.A!MTB"
        threat_id = "2147739743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\ProgramData\\" wide //weight: 1
        $x_1_2 = "klYKAnM.exe" wide //weight: 1
        $x_1_3 = {8b c1 33 d2 f7 f7 41 8a 82 ?? ?? ?? 00 30 44 31 ff 81 f9 ?? ?? 00 00 75 e7 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_A_2147739743_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.A!MTB"
        threat_id = "2147739743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 74 ?? 8b 55 08 52 e8 ?? ?? ?? ?? 83 c4 04 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 0c 03 45 fc 8b 4d 08 8a 00 32 04 11 8b 4d 0c 03 4d fc 88 01 eb}  //weight: 2, accuracy: Low
        $x_1_2 = {57 8b ec 8b c7 05 ?? ?? ?? ?? 68 f0 ff 00 00 89 45 04 59 8b d7 8b f7 8b c1 66 ad 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_3 = {51 8b c6 8b 00 46 8b 0f 33 c8 8b c1 88 07 47 4b 58 8b c8 75 06 58 2b f0 50 8b d8 49 75 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_A_2147739743_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.A!MTB"
        threat_id = "2147739743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 65 c6 85 ?? ?? ?? ?? 6c c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 74 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 20 c6 85 ?? ?? ?? ?? 57 c6 85 ?? ?? ?? ?? 69 c6 85 ?? ?? ?? ?? 6e c6 85 ?? ?? ?? ?? 44 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 66 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 6e c6 85 ?? ?? ?? ?? 64}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 20 c6 85 ?? ?? ?? ?? 53 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 74 c6 85 ?? ?? ?? ?? 2d c6 85 ?? ?? ?? ?? 4d c6 85 ?? ?? ?? ?? 70 c6 85 ?? ?? ?? ?? 50 c6 85 ?? ?? ?? ?? 72 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 66 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 72 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 6e c6 85 ?? ?? ?? ?? 63 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 20 c6 85 ?? ?? ?? ?? 2d c6 85 ?? ?? ?? ?? 44 c6 85 ?? ?? ?? ?? 69 c6 85 ?? ?? ?? ?? 73 c6 85 ?? ?? ?? ?? 61 c6 85 ?? ?? ?? ?? 62 c6 85 ?? ?? ?? ?? 6c c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 52 c6 85 ?? ?? ?? ?? 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GG_2147741117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GG!MTB"
        threat_id = "2147741117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c 8d 0c 06 33 d2 8b c6 f7 75 14 8b 45 08 8a 04 02 30 01 46 3b 75 10 75 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GB_2147741192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GB"
        threat_id = "2147741192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 68 65 20 74 72 69 63 6b 5c 59 61 6e 64 65 78 44 69 73 6b 5c 50 72 6f 6a 65 63 74 73 5c 42 6f 74 5c 42 6f 74 5f 28 31 30 30 36 29 5f 30 38 2e 31 32 2e 32 30 31 36 5c 42 6f 74 5c 47 65 74 53 79 73 74 65 6d 49 6e 66 6f 5f 73 6f 6c 75 74 69 6f 6e 5c [0-6] 5c 52 65 6c 65 61 73 65 5c 47 65 74 53 79 73 74 65 6d 49 6e 66 6f 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GS_2147741461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GS!MTB"
        threat_id = "2147741461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 8b 5c 24 0c 55 56 8b 74 24 18 33 d2 8b c1 bd [0-4] f7 f5 8a 04 1a 30 04 31 41 3b cf 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GH_2147741462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GH!MTB"
        threat_id = "2147741462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e9 d0 2a 00 00 55 8b ec 81 ec 90 04 00 00 b8 70 00 00 00 66 89 45 94 b9 61 00 00 00 66 89 4d 96 ba 79 00 00 00 66 89 55 98 b8 6c 00 00 00 66 89 45 9a b9 6f 00 00 00 66 89 4d 9c ba 61 00 00 00 66 89 55 9e b8 64 00 00 00 66 89 45 a0 b9 2e 00 00 00 66 89 4d a2 ba 65 00 00 00 66 89 55 a4 b8 78 00 00 00 66 89 45 a6 b9 65 00 00 00 66 89 4d a8 33 d2 66 89 55 aa b8 73 00 00 00 66 89 45 c4 b9 61 00 00 00 66 89 4d c6 ba 6d 00 00 00 66 89 55 c8 b8 70 00 00 00 66 89 45 ca b9 6c 00 00 00 66 89 4d cc ba 65 00 00 00 66 89 55 ce b8 2e 00 00 00 66 89 45 d0 b9 65 00 00 00 66 89 4d d2 ba 78 00 00 00 66 89 55 d4 b8 65 00 00 00 66 89 45 d6 33 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GH_2147741462_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GH!MTB"
        threat_id = "2147741462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 [0-10] 8a ?? ?? 30 ?? 31 41 3b cf 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GH_2147741462_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GH!MTB"
        threat_id = "2147741462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 d2 09 fa 88 16 c7 45 b0 8b 00 00 00 8b bd 30 ff ff ff 8a 17 0f b6 d2 8a 1e 0f b6 db 31 d3 88 1e c7 45 ac 27 01 00 00 8a 1f 80 c3 01 88 1f c7 45 a8 df 01 00 00 8a 1e 8b 95 18 ff ff ff 8b 02 88 18}  //weight: 1, accuracy: High
        $x_1_2 = "StruoNosW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GK_2147741463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GK!MTB"
        threat_id = "2147741463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 81 e2 [0-4] 79 ?? 4a 83 ca e0 42 8a 14 3a 30 14 08 40 3b c6 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GU_2147741464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GU!MTB"
        threat_id = "2147741464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 74 24 ?? b8 ?? ?? ?? ?? f7 e1 8b c1 2b c2 [0-10] 8b d1 2b d0 8a 04 1a 30 04 31 83 c1 01 3b cf 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PI_2147741571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PI"
        threat_id = "2147741571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 45 08 0f be 0c 10 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01}  //weight: 3, accuracy: Low
        $x_1_2 = {5c 54 69 6e 69 5c 64 64 73 61 6d 70 5c [0-16] 5c 64 64 73 61 6d 70 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 50 72 6f 6a 65 63 74 5f 30 31 5c [0-16] 5c 7a 47 63 72 76 6a 4a 6d 4f 58 78 66 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_RA_2147741578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RA"
        threat_id = "2147741578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 8b ec 8b c7 05 ?? ?? ?? ?? 68 f1 ff 00 00 59 89 45 04 8b d7 8b f7 49 8b c1 66 ad 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = {57 8b ec 05 ?? ?? ?? ?? 89 45 04 68 f0 ff 00 00 59 8b f7 8b d7 fc 8b c1 66 ad 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_3 = {51 8b c6 8b 00 46 8b 0f 33 c8 8b c1 88 07 47 4b 58 8b c8 75 06 58 2b f0 50 8b d8 49 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Trickbot_B_2147741634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.B!MTB"
        threat_id = "2147741634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 61 6e 64 6c 65 72 00 64 70 6f 73 74 00 00 00 69 6e 66 65 63 74}  //weight: 1, accuracy: High
        $x_1_2 = "\\svcctl" ascii //weight: 1
        $x_1_3 = "0123456789_qwertyuiopasdfghjklzxcvbnm" ascii //weight: 1
        $x_1_4 = "0123456789_qwertyuiopasdfghjklzxcvbnm" wide //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_B_2147741634_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.B!MTB"
        threat_id = "2147741634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 7d f0 83 ef 01 89 45 ec 8b 45 f0 0f af c7 83 e0 01 83 f8 00 0f 94 c0 83 fb 0a 0f 9c c4 08 e0 a8 01}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 f0 8a 44 24 1e 0f b6 f8 89 f8 31 f0 88 44 24 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GR_2147741744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GR!MTB"
        threat_id = "2147741744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 73 0c 03 f7 8b ea 3b e9 76 [0-7] 8b 44 24 14 83 78 18 ?? 72 ?? 83 c0 ?? 8b 00 eb ?? 83 c0 ?? 8a 0c 28 30 0e 8b 43 10 2b 43 0c 47 3b f8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GR_2147741744_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GR!MTB"
        threat_id = "2147741744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 8b c1 [0-8] f7 [0-2] 8b [0-3] 8a [0-2] 8a [0-4] 32 [0-4] 88 [0-2] 41 81 f9}  //weight: 10, accuracy: Low
        $x_1_2 = {73 00 66 c7 [0-4] 77 00 66 [0-4] 68 00 66 [0-4] 6b 00 66 [0-4] 2e 00 66 [0-4] 64 00}  //weight: 1, accuracy: Low
        $x_1_3 = {61 00 66 c7 [0-2] 73 00 66 c7 [0-2] 77 00 66 c7 [0-2] 68 00 66 c7 [0-2] 6f 00 66 c7 [0-2] 6f 00 66 c7 [0-2] 6b 00 66 c7 [0-2] 2e 00 66 c7 [0-2] 64 00 66 c7 [0-2] 6c 00 66 c7 [0-2] 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_C_2147741800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.C!MTB"
        threat_id = "2147741800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\" wide //weight: 1
        $x_1_2 = {33 00 34 00 32 00 31 00 4b 04 46 04 45 04 18 04 42 04 3d 04 30 04 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "McVjd0l|ePxCPg*hyTI@Hc8" ascii //weight: 1
        $x_1_4 = "Z{o8j{IXXc0c@3q" ascii //weight: 1
        $x_1_5 = "Player.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_C_2147741800_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.C!MTB"
        threat_id = "2147741800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ef 01 89 5d e0 01 fb 8b 7d e0 0f af fb 83 e7 01 83 ff 00 0f 94 c3 80 e3 01 88 5d ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PA_2147741871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PA!MTB"
        threat_id = "2147741871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 08 2b c6 3b c8 74 ?? 83 7d ?? 10 8b 5d ?? 72 ?? 8b 7d 04 eb ?? 8d 7d 04 33 d2 8b c1 f7 f3 8a 04 3a 30 04 0e 41 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\ProgramData\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PA_2147741962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PA!MSR"
        threat_id = "2147741962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 68 60 11 00 00 6a 00 ff d3 68 60 11 00 00 68 ?? ?? ?? 00 50 e8 ?? ?? ff ff 8d 54 24 0c 52 56 6a 10 68 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PI_2147741966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PI!MSR"
        threat_id = "2147741966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fuck Sophos" wide //weight: 1
        $x_1_2 = "\\CustomToolTipPlusDemo.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PI_2147741966_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PI!MSR"
        threat_id = "2147741966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 68 60 11 00 00 57 53 e8 ?? ?? ff ff 83 c4 10 6a 40 68 00 10 00 00 ff 75 fc 6a 00 e8 ?? ?? 00 00 89 45 f0 ff 75 fc ff 75 f8 ff 75 f0 e8 ?? ?? 00 00 83 c4 0c 6a 40 68 00 10 00 00 68 60 11 00 00 6a 00 e8 ?? ?? 00 00 8b f8 68 60 11 00 00 53 57 e8 ?? ?? 00 00 83 c4 0c 8d 45 fc 50 ff 75 f0 6a 10 ff 75 ec ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = "___CPPdebugHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_D_2147742052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.D!MTB"
        threat_id = "2147742052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 f2 01 20 d4 08 e0 88 ca 80 f2 ff 88 c4 20 d4 88 c2 80 f2 ff 88 ce 20 d6 08 f4 88 ca 80 f2 ff 88 c6 80 f6 ff 88 eb 80 f3 00 88 d7 80 e7 00 20 d9 88 76 37}  //weight: 1, accuracy: High
        $x_1_2 = "LoperNutW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_D_2147742052_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.D!MTB"
        threat_id = "2147742052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec a1 ?? ?? ?? 00 03 05 ?? ?? ?? 00 0f b6 08 8b 15 ?? ?? ?? 00 03 15 ?? ?? ?? 00 0f b6 02 03 c1 8b 0d ?? ?? ?? 00 03 0d ?? ?? ?? 00 88 01 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b 45 08 0f af 45 08 2d ?? ?? ?? ?? 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_E_2147742060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.E!MTB"
        threat_id = "2147742060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 8b 4d fc 8d 94 01 ?? ?? 00 00 8b 45 08 89 10 8b 4d 08 8b 11 81 ea ?? ?? 00 00 8b 45 08 89 10 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d fc 8d 94 01 ?? ?? 00 00 8b 45 08 03 10 8b 4d 08 89 11 8b 55 08 8b 02 2d ?? ?? 00 00 8b 4d 08 89 01 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c0 8b ca 8b c0 a3 ?? ?? ?? 00 8b c0 31 0d ?? ?? ?? 00 8b c0 a1 ?? ?? ?? 00 c7 05 ?? ?? ?? 00 00 00 00 00 01 05 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 89 11 5d c3}  //weight: 1, accuracy: Low
        $x_1_4 = {8b c0 8b ca 8b c0 8b d0 33 d1 8b c2 c7 05 ?? ?? ?? 00 00 00 00 00 01 05 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 89 11 5d c3}  //weight: 1, accuracy: Low
        $x_1_5 = {8b ff c7 05 ?? ?? ?? 00 00 00 00 00 a1 ?? ?? ?? 00 01 05 ?? ?? ?? 00 8b ff 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 89 02 5f 5d c3 4f 00 b8 ?? ?? ?? 00 a1 ?? ?? ?? 00 31 0d ?? ?? ?? 00 8b ff c7 05 ?? ?? ?? 00 00 00 00 00 a1}  //weight: 1, accuracy: Low
        $x_1_6 = {8b ff c7 05 ?? ?? ?? 00 00 00 00 00 01 05 ?? ?? ?? 00 8b ff 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 89 02 5f 5d c3 4f 00 b8 ?? ?? ?? 00 a1 ?? ?? ?? 00 33 c1 8b ff c7 05 ?? ?? ?? 00 00 00 00 00 01 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Trickbot_AR_2147742070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AR"
        threat_id = "2147742070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\Users\\User\\Desktop\\commap\\ctlcomm\\Release\\ctlcomm.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AG_2147742098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AG!MTB"
        threat_id = "2147742098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 be ?? ?? ?? ?? f7 fe 8a 99 ?? ?? ?? ?? 8a 92 ?? ?? ?? ?? 32 da 88 99 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 51 8b 74 24 ?? 8b 7c 24 ?? 8b 4c 24 ?? f3 a4 59 5f 5e c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BS_2147742130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BS!MTB"
        threat_id = "2147742130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 16 8d 84 3d ?? ?? ?? ?? 0f b6 d3 88 18 0f b6 06 03 c2 8b f1 99 f7 fe 8b 45 14 8a 94 15 ?? ?? ?? ?? 30 10 40 ff 4d 0c 89 45 14 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BS_2147742130_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BS!MTB"
        threat_id = "2147742130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d6 8b 45 fc 0f b6 4d 17 0f b6 84 05 ?? ?? ?? ?? 03 c1 8b cb 99 f7 f9 8b 45 08 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d f8 89 45 08 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BS_2147742130_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BS!MTB"
        threat_id = "2147742130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 8b 51 ?? 8b 79 ?? 2b d7 03 d6 66 0f b6 0a 8b f9 2b c8 66 85 c9 7d ?? 81 c1 00 01 00 00 8b 85 ?? ?? ?? ?? 88 0a 03 f0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BS_2147742130_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BS!MTB"
        threat_id = "2147742130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 f7 fb 0f b6 04 37 89 55 ?? 03 d6 8a 1a 88 1c 37 47 3b f9 88 02 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d7 8a 1a 88 19 88 02 0f b6 01 0f b6 0a 03 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BS_2147742130_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BS!MTB"
        threat_id = "2147742130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 f7 f9 8b 4c 24 ?? 33 c0 8a 04 0a 8b 54 24 ?? 0f be 0c 3a 51 50 e8 ?? ?? ?? ?? 88 07 8b 44 24 ?? 83 c4 10 47 48 89 44 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BS_2147742130_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BS!MTB"
        threat_id = "2147742130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b d8 72 10 ff 15 ?? ?? ?? ?? eb 08 ff 15 ?? ?? ?? ?? 8b d8 8b ?? ff 15 ?? ?? ?? ?? 8b [0-20] b8 01 00 00 00 03 c1 [0-6] 89 85 54 ff ff ff 8b ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BS_2147742130_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BS!MTB"
        threat_id = "2147742130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b da 3b d8 72 ?? ff 15 ?? ?? ?? ?? eb ?? ff 15 ?? ?? ?? ?? 8b d8 8b ce ff 15 ?? ?? ?? ?? 8b 0f 8b b5 ?? ?? ?? ?? 8b 51 ?? 8b 8d ?? ?? ?? ?? 88 04 1a b8 01 00 00 00 03 c1 0f 80 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BS_2147742130_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BS!MTB"
        threat_id = "2147742130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fb 2b fa 3b f9 72 ?? ff 15 ?? ?? ?? ?? eb ?? ff 15 ?? ?? ?? ?? 8b f8 dd 45 ?? ff 15 ?? ?? ?? ?? 8b 16 8b 4a ?? 88 04 39 b8 01 00 00 00 03 c3 0f 80}  //weight: 1, accuracy: Low
        $x_1_2 = {50 68 00 00 f0 3f 6a 00 68 ?? ?? ?? ?? 51 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BS_2147742130_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BS!MTB"
        threat_id = "2147742130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b de 2b da 3b d8 72 ?? ff 15 ?? ?? ?? ?? 8b c3 eb ?? ff 15 ?? ?? ?? ?? 8b 0f 8b 51 ?? 66 0f b6 1c 02 2b 5d ?? 66 85 db 7d ?? 81 c3 00 01 00 00 85 c9 74 ?? 66 83 39 01 75 1c 8b 51 ?? 8b 41 ?? 2b f2 3b f0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BS_2147742130_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BS!MTB"
        threat_id = "2147742130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 ff 00 00 00 89 84 9d ?? ?? ?? ?? 8b 84 8d ?? ?? ?? ?? 03 84 9d ?? ?? ?? ?? be e1 01 00 00 99 f7 fe 8a 84 95 ?? ?? ?? ?? 8b 55 ?? 8b 75 ?? 30 04 32 ff 45 ?? 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = "___CPPdebugHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_SA_2147742134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SA!MSR"
        threat_id = "2147742134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F:\\Custom\\Darins1.vbp" wide //weight: 1
        $x_1_2 = "\\indiana_jones_art_harrison_ford.jpg" wide //weight: 1
        $x_1_3 = "NPZ Optics State Plant.exe" wide //weight: 1
        $x_1_4 = "SHELLDLL_DefView" wide //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_SA_2147742134_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SA!MSR"
        threat_id = "2147742134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LoadShellCode" ascii //weight: 1
        $x_1_2 = "G*\\AC:\\Users\\911\\Desktop\\cButtonBar\\cButtonBar\\ButtonBar.vbp" wide //weight: 1
        $x_1_3 = "pShellCode" ascii //weight: 1
        $x_1_4 = "InitShellCode" ascii //weight: 1
        $x_1_5 = "CAZxGEU34OCFBBKCQJhWUE#$_SVRR[SQZx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_F_2147742228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.F!MTB"
        threat_id = "2147742228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec eb 00 8b 45 08 0f af 45 08 2d ?? ?? ?? ?? 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b 45 08 0f af 45 08 2d ?? ?? ?? ?? 5d c3}  //weight: 1, accuracy: Low
        $x_2_3 = {0f b6 14 30 f7 da 8b 45 f8 0f b6 08 2b ca 8b 55 f8 88 0a 5e 8b e5 5d c3}  //weight: 2, accuracy: High
        $x_2_4 = {89 45 fc 8b 0d ?? ?? ?? 00 03 0d ?? ?? ?? 00 0f b6 11 8b 45 fc 0f b6 08 03 ca 8b 55 fc 88 0a 8b e5 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_G_2147742232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.G!MTB"
        threat_id = "2147742232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "KLOEDSWAX" ascii //weight: 1
        $x_1_3 = "CLSID\\%1\\InProcServer32" ascii //weight: 1
        $x_1_4 = "%2\\protocol\\StdFileEditing\\verb\\0" ascii //weight: 1
        $x_1_5 = "CWinApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_G_2147742232_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.G!MTB"
        threat_id = "2147742232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 d0 8b 45 ?? 0f b6 14 10 8b 45 ?? 0f b6 0c 08 33 ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 75 ?? 2b f0 03 f2 2b 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 8b 55 ?? 88 0c 32 e9}  //weight: 10, accuracy: Low
        $x_10_2 = "KVt7qO2<wzb%(K10$d1oz5!8wyY#t6^ZqFqP0yNtBYC$<hwQLFIQ9zxP4sHo?q%U<0#paLGI<^fSC%*" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_SP_2147742343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SP!MSR"
        threat_id = "2147742343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca 8b c0 8b d0 33 d1 8b c2 c7 05 [0-3] 00 00 00 00 00 01 05 [0-3] 00 8b 0d [0-3] 00 8b 15 [0-3] 00 89 11}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d [0-3] 00 00 8b 4d 08 89 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_NG_2147742423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.NG!MTB"
        threat_id = "2147742423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e6 c1 ea ?? 8b c2 c1 e0 ?? 03 c2 03 c0 8b de 2b d8 8b 44 24 ?? 03 fe 3b [0-29] 8a 0c 18 30 0f 8b 45 ?? 2b 45 ?? 46 3b f0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EG_2147742424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EG!MTB"
        threat_id = "2147742424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fd 89 d1 8b 7c 94 ?? 8d 04 1f 99 f7 fd 89 d3 8b 44 ?? ?? 89 44 ?? ?? 89 fa 0f b6 c2 89 44 ?? ?? 03 44 ?? ?? 99 f7 fd 8b 44 ?? ?? 8b 54 ?? ?? 30 04 32 46 81 fe ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EG_2147742424_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EG!MTB"
        threat_id = "2147742424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c0 25 83 c0 56 99 6a 7f 59 f7 f9 88 55 ?? 33 c0 40 d1 e0 0f b6 80 ?? ?? ?? ?? 6b c0 25 83 c0 56 99 6a 7f 59 f7 f9 88 55 ?? 33 c0 40 6b c0 03 0f b6 80 ?? ?? ?? ?? 6b c0 25 83 c0 56 99 6a 7f 59 f7 f9 88 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EG_2147742424_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EG!MTB"
        threat_id = "2147742424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 e8 0f b6 02 0f b6 4d e7 33 c1 8b 55 e8 2b 55 08 0f b6 ca 81 e1 e0 00 00 00 33 c1 8b 55 e8 88 02}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 ec 83 c2 01 89 55 ec 8b 45 ec 3b 45 fc 0f 8d ?? ?? ?? ?? 8b 4d f0 03 4d ec 0f be 11 81 f2 e0 00 00 00 88 55 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EG_2147742424_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EG!MTB"
        threat_id = "2147742424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 83 c4 48 8b d0 c1 e2 05 2b d0 03 d6 ff}  //weight: 1, accuracy: High
        $x_1_2 = {57 0f af 35 ?? ?? ?? ?? 8b f9 8b c1 c1 e7 05 2b f9 2b c6 c1 e7 03 8b d0 8b df 8b 7c ?? ?? c1 e2 06 8b 54 ?? ?? 2b d3 8d 1c ?? 8d 2c ?? 8b 5c 3a ?? 03 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_SG_2147742425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SG!MTB"
        threat_id = "2147742425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 78 18 10 72 ?? 83 c0 04 8b 00 eb ?? 83 c0 04 8a 04 38 30 06 8b 45 ?? 2b 45 ?? 43 3b d8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_SR_2147742482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SR!MSR"
        threat_id = "2147742482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 15 48 d8 4b 00 03 15 d0 cd 4b 00 0f b6 02 8b 4d fc 0f b6 11 03 d0 8b 45 fc 88 10}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 fc 03 15 ?? ?? ?? ?? 8b 45 08 03 10 8b 4d 08 89 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_HG_2147742544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.HG!MTB"
        threat_id = "2147742544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 [0-9] 3b 78 14 [0-17] 83 c0 04 8b 00 eb ?? 83 c0 04 8a ?? ?? 30 ?? 8b [0-9] 3b ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KG_2147742605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KG!MTB"
        threat_id = "2147742605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 33 d2 b9 [0-4] f7 f1 [0-80] 0f be [0-2] 8b 55 ?? 0f be ?? 33 ?? 8b 4d ?? 88 ?? e9 a0 00 8b 45 fc 83 c0 01 89 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_UG_2147742650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.UG!MTB"
        threat_id = "2147742650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 8b ce e8 [0-4] 8b ?? ?? ?? 8b f8 8b ?? 83 e0 ?? 50 e8 [0-4] 8a ?? 30 ?? 8b ?? ?? 2b ?? ?? 43 3b ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BA_2147742797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BA!MTB"
        threat_id = "2147742797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 8b cb 99 f7 f9 8b 4d ?? 8b 75 ?? 0f be 0c 31 51 0f b6 04 3a 50 e8 ?? ?? ?? ?? 83 c4 10 88 06 46 ff 4d ?? 89 75 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BA_2147742797_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BA!MTB"
        threat_id = "2147742797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vtI@%9Ie@Uv|TeN%rn}#" ascii //weight: 1
        $x_1_2 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 10 8d 0c 06 33 d2 6a 14 8b c6 5b f7 f3 8b 44 24 0c 8a 04 02 30 01 46 3b 74 24 14 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BA_2147742797_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BA!MTB"
        threat_id = "2147742797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 33 c0 8a 04 11 8d 3c 11 89 85 ?? ?? ?? ?? db 85 ?? ?? ?? ?? dc 65 ?? dc 15 ?? ?? ?? ?? df e0 f6 c4 01 74 ?? dc 05 ?? ?? ?? ?? 83 ec 08 dd 1c 24 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 88 07 01 4d ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PC_2147742877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PC!MTB"
        threat_id = "2147742877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4b 04 85 c9 75 ?? 33 c0 eb ?? 8b 43 08 2b c1 3b f8 74 ?? [0-16] 8b 4b 04 8b 46 ?? 8b 5e ?? 03 cf 83 f8 ?? 72 ?? 8b 6e 04 eb ?? 8d 6e 04 33 d2 8b c7 f7 f3 8a 04 2a 30 01 47 eb}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d ?? e8 ?? ?? ?? ?? 39 45 fc 74 [0-32] 8b 4d fc 51 8b 4d ?? e8 ?? ?? ?? ?? 89 45 ?? 8b 4d ?? e8 ?? ?? ?? ?? 8b c8 8b 45 fc 33 d2 f7 f1 52 8b 4d ?? e8 ?? ?? ?? ?? 0f be 10 8b 45 ?? 0f be ?? 33 ca 8b 55 ?? 88 0a eb}  //weight: 5, accuracy: Low
        $x_5_3 = {8b 43 08 2b c1 3b f8 72 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 8b 48 ?? 33 d2 8b c7 f7 f1 8b 73 04 03 f7 8b ea 3b e9 76 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 83 78 ?? 10 72 07 83 c0 04 8b 00 eb ?? 83 c0 04 8a 0c 28 30 0e 8b c3 83 c7 01 e8 ?? ?? ?? ?? 3b f8 75}  //weight: 5, accuracy: Low
        $x_1_4 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-64] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_MG_2147742913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MG!MTB"
        threat_id = "2147742913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 74 24 ?? 55 53 8b 5c 24 ?? 8b ?? 33 ?? bd [0-4] f7 f5 8a ?? ?? 8a ?? ?? 32 ?? 88 ?? ?? 41 3b cf 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RG_2147742914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RG!MTB"
        threat_id = "2147742914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 39 4c ?? ?? 74 ?? 56 8b ?? ?? ?? 8b 74 ?? ?? 8b d1 03 c1 83 ?? ?? 8a ?? ?? 30 ?? 41 3b 4c ?? ?? 75 ?? 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DG_2147742916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DG!MTB"
        threat_id = "2147742916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 02 8b 4d ?? 03 4d ?? 81 e1 ?? ?? ?? ?? 33 d2 8a 94 ?? ?? ?? ?? ?? 33 c2 8b 4d ?? 03 4d ?? 88 01 e9 a4 00 83 c2 01 89 55 ?? 8b 45 ?? 3b 45 ?? 0f 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_SM_2147742978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SM!MTB"
        threat_id = "2147742978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 53 51 8b c6 46 8b 00 8b 0f 33 c1 88 07 47 4b 58 8b c8 75 06 58 2b f0 50 8b d8 49 75 e4 59 58 59 5e 5f 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RB_2147743034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RB!MSR"
        threat_id = "2147743034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 0c 53 57 8b 7c 24 10 8a 1c 08 8b d0 83 e2 1f 8a 14 3a 32 da 88 1c 08 40 3b c6 75 eb 5f 5b 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_J_2147743246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.J!ibt"
        threat_id = "2147743246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-64] ?? 04 ?? 04 ?? 04 ?? 04 2e 00 65 00 78 00 65 00}  //weight: 5, accuracy: Low
        $x_5_2 = {3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-64] ?? 10 ?? 10 ?? 10 ?? 10 2e 00 65 00 78 00 65 00}  //weight: 5, accuracy: Low
        $x_1_3 = {68 00 04 00 00 8d [0-9] ff 15 [0-32] ff 15 ?? ?? ?? ?? 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_WG_2147743291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.WG!MTB"
        threat_id = "2147743291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2f 00 [0-32] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f [0-6] 2e [0-6] 2e [0-6] 2e [0-6] 2f [0-32] 2e 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_3 = "InfMachine" ascii //weight: 1
        $x_1_4 = "pysmb" ascii //weight: 1
        $x_1_5 = "Size - %d kB" ascii //weight: 1
        $x_1_6 = "\\\\%s\\IPC$" ascii //weight: 1
        $x_1_7 = "MACHINE IN WORKGROUP" ascii //weight: 1
        $x_1_8 = "LDAP://%ls" ascii //weight: 1
        $x_1_9 = "(objectCategory=computer)(userAccountControl" ascii //weight: 1
        $x_1_10 = "{001677D0-FD16-11CE-ABC4-02608C9E7553}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Trojan_Win32_Trickbot_IG_2147743326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.IG!MTB"
        threat_id = "2147743326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 03 55 [0-8] 8b 4d ?? 03 4d [0-20] 33 ?? 8b ?? ?? 03 ?? ?? 88 ?? e9 9b 00 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 3b 45 [0-10] 83 c1 01 81 e1 ?? ?? ?? ?? 89 4d ?? 8b 55 [0-12] 89 45 ?? 8b 4d ?? 03 4d ?? 81 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_FG_2147743437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.FG!MTB"
        threat_id = "2147743437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 f7 ?? 8a 44 ?? ?? 8a ?? ?? 32 ?? 8b ?? ?? ?? ?? ?? ?? 88 ?? ?? 47 3b f8 72 59 00 8d [0-2] 99 b9 ?? ?? ?? ?? f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_JG_2147743438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.JG!MTB"
        threat_id = "2147743438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 5e 5d 5b 60 00 8b 74 [0-5] 81 ?? ff ?? ?? ?? 0f b6 ?? ?? ?? 03 ?? 81 ?? ff ?? ?? ?? 0f b6 ?? ?? ?? 88 44 ?? ?? 02 ?? 0f b6 ?? 88 54 ?? ?? 8a 54 ?? ?? 30 [0-5] 3b ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {41 3b cd 7c ?? 5f 5e 64 00 7e ?? 8b 9c ?? ?? ?? ?? ?? 8b 7c ?? ?? 8b 74 ?? ?? 46 81 e6 ?? ?? ?? ?? 0f b6 ?? ?? ?? 03 ?? 81 e7 ?? ?? ?? ?? 0f b6 ?? ?? ?? 88 44 ?? ?? 02 ?? 0f b6 ?? 88 54 ?? ?? 8a 54 ?? ?? 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_PD_2147743868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PD!MTB"
        threat_id = "2147743868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 04 8b 45 f4 33 d2 b9 0a 00 00 00 f7 f1 8b 45 f0 0f b6 0c 10 8b 55 f4 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d f4 88 81}  //weight: 10, accuracy: Low
        $x_1_2 = {52 6a 40 68 04 2e 00 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 45 ec 50 6a 01 b9 ?? ?? ?? ?? ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PE_2147744244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PE!MTB"
        threat_id = "2147744244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 02 8b 06 83 c6 04 8b 5d ?? 31 d8 89 07 83 c7 04 e2 ?? ff 65}  //weight: 1, accuracy: Low
        $x_20_2 = {8b 04 24 89 45 ?? 83 c4 04 8b 55 ?? 8b 12 8d bd ?? ?? ff ff 8b 75 ?? 83 c6 04 b9 31 00 00 00 8b 1e 31 d3 89 1f b8 04 00 00 00 01 c6 01 c7 49 83 f9 00 75 ?? 8b 45 ?? 66 31 c0 66 bb 4d 5a 66 39 18 74}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PF_2147744394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PF!MTB"
        threat_id = "2147744394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 51 0c 8b 59 14 8b 4d ?? 2b d3 83 c1 05 66 0f b6 04 10 66 99 66 f7 f9 66 8b da 8d 55 ?? 52 ff d6 8a 04 38 8d 4d ?? 51 32 d8 ff d6 8b 4d ?? 88 1c 38 8b 7d 0c b8 01 00 00 00 03 c8 33 db 89 4d ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 d4 8b 95 ?? ?? ?? ?? 8b 5d ?? 8b 48 0c 66 0f b6 04 11 66 8b cb 66 83 c1 05 66 99 0f 80 ?? ?? ?? ?? 66 f7 f9 66 8b ca 8b 16 8b 42 0c 8b 95 ?? ?? ?? ?? 66 0f b6 04 10 33 c8 ff 15 ?? ?? ?? ?? 8b 0e 8b 51 0c 88 04 3a b8 01 00 00 00 66 03 c3 bf 02 00 00 00 0f 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_PG_2147744457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PG!MTB"
        threat_id = "2147744457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 0c 01 00 00 00 c7 44 24 08 10 00 00 00 8b 55 10 89 54 24 04 89 04 24 c7 85 ?? ?? ?? ?? 01 00 00 00 ff d1 83 ec 10 85 c0 0f 94 c0 84 c0 74 ?? b8 00 00 00 00 e9 ?? ?? ?? ?? 8b 5d ?? 8b 55 ?? 8b 45 ?? 8d 4d ?? 89 4c 24 10 c7 44 24 0c 01 00 00 00 89 54 24 08 c7 44 24 04 01 68 00 00 89 04 24 c7 85 ?? ?? ?? ?? 01 00 00 00 ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 ac 5a 50 53 5a c7 45 b0 65 62 62 64 c7 45 b4 64 4a 63 4c c7 45 b8 76 74 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BZ_2147744599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BZ!MTB"
        threat_id = "2147744599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 03 55 ec 33 c0 8a 02 8b 4d fc 03 4d f8 81 e1 ff 00 00 00 33 d2 8a 94 0d e4 fe ff ff 33 c2 8b 4d 08 03 4d ec 88 01 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BZ_2147744599_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BZ!MTB"
        threat_id = "2147744599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0e 8b c3 8b 51 0c 8b 59 14 2b d3 03 d7 66 0f b6 0a 8b d9 2b c8 66 85 c9 7d 06 81 c1 00 01 00 00 8b 85 30 ff ff ff 88 0a 03 f8 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_SU_2147744747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SU!MSR"
        threat_id = "2147744747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ANIMTEST MFC Application" wide //weight: 1
        $x_1_2 = {8b 17 2b d3 89 17 89 79 08 5f 5e 5d 5b 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RL_2147745123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RL!MTB"
        threat_id = "2147745123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 d7 89 fa 88 16 41 81 e1 ?? ?? ?? ?? 8b 7c 88 ?? 8b 14 24 01 fa 81 e2 ?? ?? ?? ?? 89 14 24 8b 6c ?? ?? 89 6c 88 ?? 89 7c ?? ?? 01 ef 81 e7 ?? ?? ?? ?? 8b 7c b8 ?? 8a ?? ?? 31 d7 89 fa 88}  //weight: 2, accuracy: Low
        $x_2_2 = {31 c8 89 d1 c1 e1 ?? c1 f9 ?? 81 e1 ?? ?? ?? ?? 31 c8 c1 e2 ?? c1 fa ?? 81 e2 ?? ?? ?? ?? 31 d0 0f b6 53 ?? 43 85 d2 0f 85 ?? ?? ?? ?? f7 d0 5b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_SJ_2147745434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SJ!MSR"
        threat_id = "2147745434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&Self Destruct" wide //weight: 1
        $x_1_2 = "&Execute Remote Program" wide //weight: 1
        $x_1_3 = "secret_controller MFC Application" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_M_2147745530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.M!MSR"
        threat_id = "2147745530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 00 6f 00 64 00 6f 00 6e 00 00 00 6e 00 65 00 77 00 73 00 00 00 00 00 2e 00 2f 00 00 00 00 00 63 00 6f 00 6d 00 2f 00 6b 00 6a 00 73 00 00 00 64 00 66 00 68 00 6e 00 76}  //weight: 2, accuracy: High
        $x_1_2 = "Update your Microsoft Word to Microsoft Word 2019 to preview this document or try on another computer with Microsoft Word" wide //weight: 1
        $x_1_3 = "HttpOpenRequestW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GI_2147745749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GI!MTB"
        threat_id = "2147745749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 24 8b 45 fc 33 d2 f7 75 14 8b 45 10 0f be 0c 10 8b 55 08 03 55 fc 0f be 02 33 c1 8b 4d 08 03 4d fc 88 01 eb cb}  //weight: 1, accuracy: High
        $x_1_2 = {b9 6b 00 00 00 66 89 8d 6c ff ff ff ba 65 00 00 00 66 89 95 6e ff ff ff b8 72 00 00 00 66 89 85 70 ff ff ff b9 6e 00 00 00 66 89 8d 72 ff ff ff ba 65 00 00 00 66 89 95 74 ff ff ff b8 6c 00 00 00 66 89 85 76 ff ff ff b9 33 00 00 00 66 89 8d 78 ff ff ff ba 32 00 00 00 66 89 95 7a ff ff ff b8 2e 00 00 00 66 89 85 7c ff ff ff b9 64 00 00 00 66 89 8d 7e ff ff ff ba 6c 00 00 00 66 89 55 80 b8 6c 00 00 00 66 89 45 82 33 c9 66 89 4d 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_C_2147745771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.C!MSR"
        threat_id = "2147745771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 73 00 74 00 70 00 00 00 61 00 00 00 6a 00 65 00 74 00 00 00 73 00 69 00 6e 00 67 00 00 00 00 00 68 00 62 00 00 00 00 00 61 00 64 00 64 00 00 00 61 00 6e 00 2e 00 00 00 63 00 61 00 6d 00 65 00 00 00 00 00 6b 00 6a 00 6c 00 64 00 00 00 00 00 66 00 6b 00 64 00 73 00}  //weight: 2, accuracy: High
        $x_1_2 = "Update your Microsoft Word to Microsoft Word 2019 to preview this document or try on another computer with Microsoft Word" wide //weight: 1
        $x_1_3 = "HttpOpenRequestW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_D_2147747973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.D!MSR"
        threat_id = "2147747973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "l#JnKU3X{" ascii //weight: 1
        $x_1_2 = "~%AE#psRBKXnhQeol$lT*w$Ui5Gam?XQn7$jesP1@aXT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_E_2147747974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.E!MSR"
        threat_id = "2147747974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 45 d8 50 68 00 00 08 00 56 53 ff 15 90 e1 40 00 8b f8 85 ff 74 3e 8b 4d d8 85 c9 74 2f 33 c0 85 c9 74 0c}  //weight: 1, accuracy: High
        $x_1_2 = {80 34 30 74 40 8b 4d d8 3b c1 72 f4}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 8d 45 cc c7 45 cc 00 00 00 00 50 51 56 ff 75 c8 ff 15 1c e0 40 00 8b 4d d8 8b f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PH_2147748069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PH!MTB"
        threat_id = "2147748069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 16 8b 54 24 ?? 8b 34 24 8a 2c 32 30 e9 8b 54 24 ?? 88 0c 32 46 66 8b 7c 24 ?? 66 81 c7 ?? ?? 66 89 7c 24 ?? 89 5c 24 ?? 89 74 24 ?? 8b 5c 24 ?? 8b 54 24 ?? 01 db 11 d2 89 5c 24 ?? 89 54 24 ?? 89 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 54 24 ?? 39 d6 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 74 24 10 8a 2c 16 88 2c 1e 88 0c 16 c7 44 24 50 ?? ?? ?? ?? 0f b6 14 1e 8b 7c 24 04 01 fa 88 d1 0f b6 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_F_2147748072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.F!MSR"
        threat_id = "2147748072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c9 81 e5 ?? ?? ?? ?? 33 c0 8a 4c 2c 10 03 d9 81 e3 ?? ?? ?? ?? 8a 44 1c 10 88 44 2c 10 02 c1 25 ff 00 00 00 88 4c 1c 10 8a 0c 32 8a 44 04 10 32 c8 88 0c 32 42 3b d7 7c c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RD_2147748117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RD!MSR"
        threat_id = "2147748117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 9c 24 4c 01 00 00 8d 54 04 14 33 c0 8a 02 8a 1c 1e 03 d8 03 d9 81 e3 ff 00 00 00 8b cb 8a 5c 0c 14 88 1a 88 44 0c 14 8d 46 01 99 f7 bc 24 50 01 00 00 8b 44 24 10 40 3d 2b 01 00 00 89 44 24 10 8b f2 7c bb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RND_2147748475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RND!MTB"
        threat_id = "2147748475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 3e 46 3b 74 24 ?? 7c f1}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 10 25 ff 7f 00 00 8b e5 5d 30 00 c7 45 ?? 43 94 0e 00 81 45 ?? 7e 0a 18 00 69 0d ?? ?? ?? ?? fd 43 03 00 8b 45 ?? 83 c0 02 03 c1 a3}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 03 8b 4c 24 ?? 03 c6 68 fc 7d 44 00 51 50 e8 ?? ?? ?? ?? 83 c4 0c 50 e8 ?? ?? ?? ?? 3b 44 24 ?? 74 ?? 8b 47 ?? 45 83 c3 04 3b e8 72}  //weight: 2, accuracy: Low
        $x_2_4 = "cuKuoiolzZlOhpgGcded" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_CF_2147748507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.CF!MTB"
        threat_id = "2147748507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d6 8b 75 ?? 8d 04 0a 66 8b 14 5e 66 03 14 7e 66 83 e2 0f 79 ?? 66 4a 66 83 ca f0 66 42 0f bf d2 8a 14 56 30 10 b8 01 00 00 00 03 c8 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_ARN_2147748522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ARN!MSR"
        threat_id = "2147748522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3a 5c 55 73 65 72 73 5c 55 73 65 72 5c 44 65 73 6b 74 6f 70 5c 32 30 30 38 5c 43 4e 65 74 77 6f 72 6b 69 6e [0-20] 5c 53 61 6d 70 6c 65 5c 52 65 6c 65 61 73 65 5c 43 4e 65 74 77 6f 72 6b 69 6e 67 2e 70 64 62}  //weight: 2, accuracy: Low
        $x_2_2 = "CNetworking.exe" ascii //weight: 2
        $x_1_3 = "Please enter your message (max. 64 Characters):" wide //weight: 1
        $x_1_4 = "Please enter the name of the file you want to send:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_RS_2147748619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RS!MSR"
        threat_id = "2147748619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 a5 68 8c 44 45 00 e8 9b fd ff ff 83 c4 0c ff d3 6a 00 6a 00 68 84 44 45 00 6a 00 ff 15 a8 04 42 00}  //weight: 1, accuracy: High
        $x_1_2 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_3 = "Erase everything" wide //weight: 1
        $x_1_4 = "Open this document" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_VSK_2147748660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.VSK!MTB"
        threat_id = "2147748660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "iHZLCvyXtDsLvh6C08FWGUnqJVf4w" ascii //weight: 2
        $x_2_2 = "igRKpVqJfBeoH1gMAvSrDUD5no7fEs" ascii //weight: 2
        $x_2_3 = "hHdYwAuKnxok5B5nrCpYR0Kiea" ascii //weight: 2
        $x_2_4 = "h1oTon5DuB7vexFtF1rcT871" ascii //weight: 2
        $x_2_5 = "i4JVRErO5FctMVeL6kf2agCBY6JBhu" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_VSK_2147748660_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.VSK!MTB"
        threat_id = "2147748660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 19 8b 45 ec 89 c1 81 c1 01 00 00 00 89 4d ec 88 18 8b 45 d4 8b 4d ac 01 c8 89 45 d4 eb}  //weight: 2, accuracy: High
        $x_2_2 = {8b c1 33 d2 bd 3f 00 00 00 f7 f5 8a 04 1a 8a 14 31 32 d0 88 14 31 41 3b cf 75}  //weight: 2, accuracy: High
        $x_2_3 = {66 8b 75 d6 66 81 f6 25 79 66 89 75 d6 80 f2 4b 88 55 cb 8b 45 d0 05 ff ff ff ff 89 45 d0 eb}  //weight: 2, accuracy: High
        $x_2_4 = {8b 4d d0 03 4d d8 0f be 19 e8 ?? ?? ?? ?? 33 d8 8b 55 d0 03 55 d8 88 1a eb}  //weight: 2, accuracy: Low
        $x_2_5 = {8b 4c 24 70 8b 54 24 18 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b f7 c1 ee 05 03 74 24 64 03 d9 03 d7 33 da 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_GP_2147749081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GP!MTB"
        threat_id = "2147749081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 [0-6] 64 a1 30 00 00 00 89 45 [0-1] 8b 45 [0-6] 8b e5 5d c3 [0-255] b9 6f 00 00 00 66 [0-4] 61 00 66 [0-4] 66 [0-4] b9 6c 00 00 00 66 [0-4] 73 00 66 [0-4] 77 00 66 [0-4] 68 00 66 [0-4] 6b 00 66 [0-4] 2e 00 66 [0-4] 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 [0-6] 64 a1 30 00 00 00 89 45 [0-1] 8b 45 [0-6] 8b e5 5d c3 [0-255] 61 00 66 c7 [0-4] 73 00 66 [0-4] 77 00 66 [0-4] 68 00 66 [0-4] 6f 00 66 [0-4] 6f 00 66 [0-4] 6b 00 66 [0-4] 2e 00 66 [0-4] 64 00 66 [0-4] 6c 00 66 [0-4] 6c 00 66 [0-4] 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {f7 d8 1b c0 59 f7 d8 48 c3}  //weight: 1, accuracy: High
        $x_1_4 = {51 3d 00 10 00 00 8d [0-5] 81 e9 00 10 00 00 2d 00 10 00 00 85 01 3d 00 10 00 00 [0-4] 8b c4 85 01 [0-4] 8b [0-4] 50 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Trickbot_DHA_2147749135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHA!MTB"
        threat_id = "2147749135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 76 00 8b b5 ?? ?? ?? ?? 89 c8 31 d2 f7 76 f4 0f b6 04 16 30 04 0b 83 c1 01 39 f9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DHB_2147749136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHB!MTB"
        threat_id = "2147749136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 89 45 00 ff 15 ?? ?? ?? ?? 8b 55 00 8b 44 24 ?? 6a 00 6a 00 56 52 6a 01 50 53 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 0c 6a 00 6a 40 68 00 30 00 00 50 6a 00 55 ff d3 8b 4c 24 ?? 8b 54 24 ?? 51 8b f0 52 56 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_MIB_2147749324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MIB!MTB"
        threat_id = "2147749324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf e0 07 00 00 6a 40 68 00 30 00 00 57 56 ff 75 ?? 89 45 ?? 2b df ff 55 ?? 57 8b 7d ?? 89 45 ?? 8d 0c 1f 51 50 ff 55 ?? 83 c4 0c 56 6a 40 68 00 30 00 00 53 56 ff 75 ?? ff 55 ?? 8b f0 53 57 56 ff 55 ?? 83 c4 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MIL_2147749326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MIL!MTB"
        threat_id = "2147749326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b c1 bf 29 00 00 00 f7 f7 8b 7c 24 0c 8a 04 39 8a 54 14 44 32 c2 88 04 39 41 81 f9 e0 07 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_CRYP_2147750234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.CRYP"
        threat_id = "2147750234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 10 00 00 [0-2] 59 [0-2] 52 e2 fd [0-3] 8b ec [0-2] 05 ?? ?? ?? ?? 68 f1 ff 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_H_2147750315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.H!MTB"
        threat_id = "2147750315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d6 8b 4c 24 14 33 c0 8a 44 3c 18 81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 45 00 8a 54 14 18 32 c2 88 45 00 8b 44 24 10 45 48 89 44 24 10 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_SRV_2147750726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SRV!MTB"
        threat_id = "2147750726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf e0 07 00 00 6a 40 68 00 30 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 2b df ff 55 ?? ?? ?? ?? ?? ?? ?? ?? 8d 0c 1f ?? ?? ff 55 ?? 83 c4 0c ?? 6a 40 68 00 30 00 00 ?? ?? ff 75 ?? ff 55 ?? 8b f0 ?? ?? ?? ff 55 ?? 8d 45 ?? 6a ?? ?? ?? ?? ff 55 ?? 83 c4 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KMG_2147751545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KMG!MTB"
        threat_id = "2147751545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 99 f7 f9 0f b6 04 2b 8b f2 8a 14 2e 88 14 2b 88 04 2e 0f b6 0c 2e 0f b6 04 2b 03 c1 99 b9 ?? ?? ?? ?? f7 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KMG_2147751545_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KMG!MTB"
        threat_id = "2147751545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c0 ec 02 80 e4 0f 0a e1 8b 4c 24 ?? 88 64 24 ?? 88 44 24 ?? 88 47 ?? 0f b7 44 24 ?? 66 89 07 83 44 24 08 03 8b 44 24 ?? 40 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KMG_2147751545_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KMG!MTB"
        threat_id = "2147751545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3b df 7e ?? 8b 4c 24 ?? 8d 4c 19 ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c3 7c ?? 8d 43 01 c6 83 ?? ?? ?? ?? 00 83 f8 3e 7d}  //weight: 1, accuracy: Low
        $x_1_2 = "8Bhf1AQAb88M@rw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KMG_2147751545_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KMG!MTB"
        threat_id = "2147751545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3b df 7e ?? 8b 4c 24 ?? 8d 4c 19 ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c3 7c ?? 8d 43 01 c6 83 ?? ?? ?? ?? 00 83 f8 3e 7d}  //weight: 1, accuracy: Low
        $x_1_2 = "odq@)d5V0f%R1&P" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KMG_2147751545_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KMG!MTB"
        threat_id = "2147751545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3b df 7e ?? 8b 4c 24 ?? 8d 4c 19 ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c3 7c ?? 8d 43 01 c6 83 ?? ?? ?? ?? 00 83 f8 3e 7d}  //weight: 1, accuracy: Low
        $x_1_2 = "z1>g>aUfQ+7hc9>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KMG_2147751545_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KMG!MTB"
        threat_id = "2147751545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 c7 45 8c 00 01 00 00 c7 45 ?? 02 00 00 00 ff 15 ?? ?? ?? ?? 8b d0 8d 4d ?? ff 15 ?? ?? ?? ?? 8d 4d ?? 51 ff 15 ?? ?? ?? ?? 8b 56 ?? 8b 4e ?? 2b d1 88 04 1a 8b 85 ?? ?? ?? ?? 03 d8 e9 ?? ?? ?? ?? 68 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KMG_2147751545_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KMG!MTB"
        threat_id = "2147751545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 3b fb 7e ?? 8d 87 ?? ?? ?? ?? 8a 08 88 8e ?? ?? ?? ?? 46 48 3b f7 7c ?? 8d 47 ?? 83 f8 3e 88 9f ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
        $x_1_2 = "ESET hyunya" ascii //weight: 1
        $x_1_3 = "b)X!QMBJI_xTAvJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KMG_2147751545_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KMG!MTB"
        threat_id = "2147751545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3b fb 7e ?? 8b 54 24 ?? 8d 4c 3a ?? 8b ff 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c7 7c ?? 8d 47 01 83 f8 3e 88 9f ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
        $x_1_2 = "#oq44d2?E1AV10k" ascii //weight: 1
        $x_1_3 = "Stup windows defender hahah" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_ACN_2147751662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ACN!MSR"
        threat_id = "2147751662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3a 5c 42 75 79 5c 73 74 6f 72 65 5c 6b 69 6e 67 5c 46 65 77 5c 43 68 61 6e 67 65 [0-20] 5c 4f 63 65 61 6e 66 75 6e 2e 70 64 62}  //weight: 2, accuracy: Low
        $x_1_2 = "canparent.dll" ascii //weight: 1
        $x_1_3 = "templ.dll" ascii //weight: 1
        $x_1_4 = {00 45 52 4e 45 4c 33 32 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = "https://www.wentspend.ru/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_AN_2147751739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AN!MTB"
        threat_id = "2147751739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 6a 12 8b 45 04 83 c0 18 5b 8b f0 53 51 8b 0f 8b 06 33 c1 88 07 46 47 4b 58 8b c8 75 06 58 2b f0 50 8b d8 49 75 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AN_2147751739_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AN!MTB"
        threat_id = "2147751739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 09 89 4e 08 8b 54 3a fc 8b fa 2b f9 89 7e 0c 76 1b 33 ff 33 f6 46 83 ff ?? 7f 0b 8a 1c 38 03 fe 30 19 03 ce eb 02 33 ff 3b ca 72 ea 5f 5b 5e 33 c0 c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_VDP_2147751744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.VDP!MTB"
        threat_id = "2147751744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 34 85 47 92 ?? 10 88 ?? ?? ?? ?? ?? eb}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 1c 10 8b 7c 24 14 8a 3c 37 30 df 8b 74 24 18 88 3c 16}  //weight: 2, accuracy: High
        $x_2_3 = "505VSU2mj6wal6eR3aDcm" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_AK_2147751805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AK!MTB"
        threat_id = "2147751805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c1 f7 75 0c 8a 5c 0c 50 0f b6 c3 41 0f b6 14 3a 03 d6 03 c2 33 d2 be e2 ?? ?? ?? f7 f6 8b f2 8a 44 34 50 88 44 0c 4f 88 5c 34 50 81 f9 e2 00 72 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AK_2147751805_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AK!MTB"
        threat_id = "2147751805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/%s/%s/5/%s/" ascii //weight: 1
        $x_1_2 = "/5/spk/" ascii //weight: 1
        $x_1_3 = "pwgrab" ascii //weight: 1
        $x_1_4 = "mcconf" ascii //weight: 1
        $x_1_5 = "autorun" ascii //weight: 1
        $x_1_6 = "/srv" ascii //weight: 1
        $x_1_7 = "186.71.150.23" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KDP_2147752426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KDP!MTB"
        threat_id = "2147752426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {58 5b b9 01 00 00 00 6b c9 00 c6 44 0d e4 ?? 50 53}  //weight: 2, accuracy: Low
        $x_2_2 = {58 5b ba 01 00 00 00 c1 e2 00 c6 44 15 e4 ?? 50 53}  //weight: 2, accuracy: Low
        $x_2_3 = {58 5b b8 01 00 00 00 d1 e0 c6 44 05 e4 ?? 50 53}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AK_2147752442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AK!MTB!!Trickbot.AK!MTB"
        threat_id = "2147752442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        info = "Trickbot: an internal category used to refer to some threats"
        info = "AK: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "pwgrab" ascii //weight: 3
        $x_1_2 = "/%s/%s/5/%s/" ascii //weight: 1
        $x_1_3 = "/5/spk/" ascii //weight: 1
        $x_1_4 = "mcconf" ascii //weight: 1
        $x_1_5 = "autorun" ascii //weight: 1
        $x_1_6 = "186.71.150.23" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_MST_2147752450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MST!MTB"
        threat_id = "2147752450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 3e 8b c6 83 e0 1f 8a 0c 18 8b 44 24 ?? 32 d1 88 14 3e 46 3b f0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 33 d2 bd 25 00 00 00 f7 f5 8a 04 1a 8a 14 31 32 d0 88 14 31 41 3b cf}  //weight: 1, accuracy: High
        $x_1_3 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_4 = "DHtmlEditDemo.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Trickbot_KSP_2147752508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KSP!MTB"
        threat_id = "2147752508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d7 8a 16 6a 00 32 d3 02 d3 88 16 ff d7 46 4d 75}  //weight: 2, accuracy: High
        $x_2_2 = {8b c6 f7 f3 8b 44 24 ?? 8a 04 02 30 01 46 3b 74 24 ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_SS_2147752770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SS"
        threat_id = "2147752770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {c0 e0 02 c0 e2 04 c0 ec 04 80 e4 03 0a e0 8a 44 [0-16] c0 e0 06 02 44 ?? ?? c0 ee 02 80 e6 0f 0a f2}  //weight: 20, accuracy: Low
        $x_10_2 = {02 f8 ff ff 85 [0-64] 83 ?? 68 75 [0-16] 83 ?? 74 75 [0-16] 83 ?? 74 75 [0-16] 83 ?? 70 75 [0-16] 83 ?? 73}  //weight: 10, accuracy: Low
        $x_10_3 = {0c 41 41 41 41 1c 00 81 ?? 41 41 41 41 75 ?? 81 ?? 04 41 41 41 41 75 ?? 81 ?? 08 41 41 41 41 75}  //weight: 10, accuracy: Low
        $x_10_4 = {58 68 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 50 e9 ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 83 ?? f4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_C_2147752772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.C!!Trickbot.C"
        threat_id = "2147752772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "Trickbot: an internal category used to refer to some threats"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 f2 ff 00 00 89 45 04 59 8b d7 49 8b f2 49 05 00 05}  //weight: 2, accuracy: Low
        $x_2_2 = {e8 00 00 00 00 58 89 c3 05 3a 05 00 00 81 c3 ?? ?? ?? ?? 68 01 00 00 00 68 05 00 00 00 53 68 45 77 62 30 50 e8 04 00 00 00 83 c4 14 c3 83 ec 48 83 64 24 18 00 b9 4c 77 26 07}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 74 24 10 8b 44 16 24 8d 04 58 0f b7 0c 10 8b 44 16 1c 8d 04 88 8b 04 10 03 c2 eb db 4d 5a 80}  //weight: 1, accuracy: High
        $x_1_4 = {8d 40 00 00 00 00 [0-32] 05 8b ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_C_2147752772_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.C!!Trickbot.C"
        threat_id = "2147752772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "Trickbot: an internal category used to refer to some threats"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {c0 e0 02 c0 e2 04 c0 ec 04 80 e4 03 0a e0 8a 44 [0-16] c0 e0 06 02 44 ?? ?? c0 ee 02 80 e6 0f 0a f2}  //weight: 20, accuracy: Low
        $x_10_2 = {02 f8 ff ff 85 [0-64] 83 ?? 68 75 [0-16] 83 ?? 74 75 [0-16] 83 ?? 74 75 [0-16] 83 ?? 70 75 [0-16] 83 ?? 73}  //weight: 10, accuracy: Low
        $x_10_3 = {0c 41 41 41 41 1c 00 81 ?? 41 41 41 41 75 ?? 81 ?? 04 41 41 41 41 75 ?? 81 ?? 08 41 41 41 41 75}  //weight: 10, accuracy: Low
        $x_10_4 = {58 68 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 50 e9 ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 83 ?? f4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_DDE_2147752785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DDE!MTB"
        threat_id = "2147752785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 14 8b 54 24 18 8b c1 8b f2 f7 d0 f7 d6 5f 0b c6 5e 0b ca 5d 23 c1 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DHC_2147752827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHC!MTB"
        threat_id = "2147752827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c 8b 55 08 89 d1 09 c1 8b 45 0c 8b 55 08 21 d0 f7 d0 21 c8 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DHD_2147753009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHD!MTB"
        threat_id = "2147753009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 1c 8b 54 24 20 8b c1 8b f2 f7 d0 f7 d6 83 c4 ?? 0b c6 0b ca 23 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DHE_2147753010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHE!MTB"
        threat_id = "2147753010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8d 0c 07 8b c7 f7 75 ?? 8b 45 ?? 8a 04 50 30 01 [0-3] 3b 7d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DHF_2147753011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHF!MTB"
        threat_id = "2147753011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ff 75 b0 53 ff 55 c4 ff 75 b0 89 45 d0 ff 75 ac 50 e8 ?? ?? ?? ?? 57 6a ?? 68 ?? ?? ?? ?? ff 75 a8 56 ff 55 d0 83 c4 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KSV_2147753108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KSV!MTB"
        threat_id = "2147753108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 0c 59 33 d2 8b c6 f7 f1 c7 04 24 ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MMB_2147753155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MMB!MTB"
        threat_id = "2147753155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a d3 22 d0 8b 44 24 ?? 88 14 08 40 89 44 24 ?? 3b 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = "AllocExNuma" ascii //weight: 1
        $x_1_3 = "aKERNEL32.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_ME_2147753181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ME"
        threat_id = "2147753181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 65 78 65 63 [0-1] 2e 64 6c 6c 00 43 6f 6e 74 72 6f 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {57 61 6e 74 c7 ?? ?? 52 65 6c 65 c7 ?? ?? 61 73 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 01 8d [0-16] ff 15 ?? ?? ?? ?? 85 c0 74 23 6a 00 6a 02 68 00 00 00 a0 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_SV_2147753314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SV!MSR"
        threat_id = "2147753314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ESTR_PASS_" ascii //weight: 1
        $x_1_2 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" ascii //weight: 1
        $x_1_3 = "Microsoft_WinInet_*" wide //weight: 1
        $x_2_4 = "bRS8yYQ0APq9xfzC" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_RB_2147753357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RB!MTB"
        threat_id = "2147753357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 81 ec 14 02 00 00 c7 45 f8 00 00 00 00 c7 85 28 fe ff ff 00 00 00 00 c7 85 2c fe ff ff 00 00 00 00 c7 85 ec fd ff ff 4c 00 00 00 b8 6b 00 00 00 66 89 85 f0 fd ff ff b9 65 00 00 00 66 89 8d f2 fd ff ff ba 72 00 00 00 66 89 95 f4 fd ff ff b8 6e 00 00 00 66 89 85 f6 fd ff ff b9 65 00 00 00 66 89 8d f8 fd ff ff ba 6c 00 00 00 66 89 95 fa fd ff ff b8 33 00 00 00 66 89 85 fc fd ff ff b9 32 00 00 00 66 89 8d fe fd ff ff ba 2e 00 00 00 66 89 95 00 fe ff ff b8 64 00 00 00 66 89 85 02 fe ff ff b9 6c 00 00 00 66 89 8d 04 fe ff ff ba 6c 00 00 00 66 89 95 06 fe ff ff 33 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RC_2147753358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RC!MTB"
        threat_id = "2147753358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4b 01 b8 ?? ?? ?? ?? f7 e9 c1 fa ?? 89 d3 89 c8 c1 f8 ?? 29 c3 69 db ?? ?? ?? ?? 29 d9 89 cb 89 cf 03 7c 24 ?? 0f b6 0f 01 f1 b8 ?? ?? ?? ?? f7 e9 89 d6 c1 fe ?? 89 c8 c1 f8 ?? 29 c6 69 f6 ?? ?? ?? ?? 29 f1 89 ce 89 c8 03 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 3c 24 e8 ?? ?? ?? ?? 0f b6 17 8b 44 24 ?? 0f b6 00 01 d0 8b 54 24 ?? 0f b6 04 02 89 ef 03 7c 24 ?? 8b 54 24 ?? 0f be 14 2a 89 54 24 ?? 89 04 24 e8 ?? ?? ?? ?? 88 07 83 c5 ?? 3b 6c 24 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KM_2147753359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KM!MTB"
        threat_id = "2147753359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 d2 f6 d1 0a d1 22 d3 83 c4 0c 88 10 40 ff 4d ?? 89 45 ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KM_2147753359_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KM!MTB"
        threat_id = "2147753359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3b fb 7e ?? 8b 54 24 ?? 8d 4c 3a ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c7 7c ?? 8d 47 ?? 83 f8 3e 88 9f ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
        $x_1_2 = "ESET hyunya" ascii //weight: 1
        $x_1_3 = "fC0)GvTWSjm*yEB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DHH_2147753452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHH!MTB"
        threat_id = "2147753452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 6a 0a 68 ?? ?? ?? ?? 53 8b e8 ff 54 24 ?? 8b f0 56 53 ff 54 24 ?? 56 53 89 44 24 ?? ff 54 24 ?? 8b 4c 24 ?? 51 89 44 24 ?? ff 54 24 ?? 8b 94 24 ?? ?? ?? ?? 53 52 89 44 24 ?? 8b 44 24 ?? 68 00 30 00 00 50 53 ff d5 50 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_KRP_2147753509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.KRP!MTB"
        threat_id = "2147753509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 0c 10 8b 55 f4 0f b6 84 15 ?? ?? ff ff 33 c1 8b 4d f4 88 84 0d ?? ?? ff ff eb 06 00 8b 85 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = "XWFTPHFMWOMZQGISZZZBCDIAQQJTRLDGCOCRCORHMMJKTRWYAJHRDVUTOFCYYMUKL" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_SK_2147753721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SK!MTB"
        threat_id = "2147753721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 59 ff d7 c6 45 b7 01 eb ?? 55 8b ec 51 53 8b 1d ?? ?? ?? ?? 56 57 33 c0}  //weight: 2, accuracy: Low
        $x_2_2 = {8b fa 8d 84 3d ?? ?? ff ff 8a 10 88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 85 ?? ?? ff ff 8a 94 15 ?? ?? ff ff 30 10 40 83 bd ?? ?? ff ff 00 89 85 ?? ?? ff ff 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_SK_2147753721_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SK!MTB"
        threat_id = "2147753721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 83 ec 40 68 ?? ?? 00 00 ff 15 ?? ?? 00 10 83 3d ?? ?? 00 10 00 74 ec c7 45 ?? 57 61 6e 74 c7 45 ?? 52 65 6c 65 c7 45 ?? 61 73 65 00 ff 35 ?? ?? 00 10 6a 00 6a 00 6a 00 6a 00 8d 45 ?? 50 ff 35 ?? ?? 00 10 ff 15 ?? ?? 00 10}  //weight: 2, accuracy: Low
        $x_2_2 = {51 8b c6 46 8b 0f 8b 00 33 c8 58 88 0f 47 4b 8b c8 75 06 58 2b f0 50 8b d8 49 75 e4 59 58 59 5e 5f 5b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 03 83 c4 0c 8a 54 14 ?? 32 c2 88 03 43 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 42 1a 00 00 f7 f9 0f b6 94 15 ?? ?? ?? ?? 30 53 ff 83 7d 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d 0c 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 85 ?? ?? ?? ?? 40 83 c4 04 89 85 ?? ?? ?? ?? 0f b6 94 15 ?? ?? ?? ?? 30 50 ff 83 bd ?? ?? ?? ?? 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 44 24 ?? 8a 18 83 c4 0c 8a 54 14 ?? 32 da 88 18 40 89 44 24 ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 55 02 00 00 f7 f9 8b 44 24 ?? 40 83 c4 38 89 44 24 ?? 0f b6 54 14 ?? 30 50 ff 83 bc 24 84 02 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8a 03 83 c4 0c 8a 54 14 ?? 32 c2 88 03 43 4d}  //weight: 1, accuracy: Low
        $x_1_2 = "MCdM1Aw|2SaG2rdGzyI3U7$K%vetuiV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 53 6a 01 53 50 ff 15 ?? ?? ?? ?? 85 c0 5b 0f 95 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 3b f3 7e ?? 8b 4c 24 ?? 8d 4c 31 ?? ?? 8a 11 88 ?? ?? ?? ?? ?? 83 c0 01 83 e9 01 3b c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 85 ?? ?? ?? ?? 8d 7f 01 8a 8c 15 ?? ?? ?? ?? 30 4f ff 4e}  //weight: 1, accuracy: Low
        $x_1_2 = "yKatBbgDwU6xylhQmVhFPesy6dLOzLvdV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 4f ff 4e 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "gABupaeV9zawahoREO5222Vf31A6N7iPAE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0f 83 c3 01 0f 80 ?? ?? ?? ?? 8b 51 0c 88 04 2a 8b 44 24 10 3b d8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 8b b4 24 4c 01 00 00 56 50 e8 ?? ?? ?? ?? 8b 4c 24 ?? 81 e1 ff ff 00 00 81 f9 4d 5a 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "xhmztFBTPqvi7TycaZlHb22SpoGiLN06Z5XooWf" ascii //weight: 1
        $x_1_2 = {f7 f9 0f b6 94 15 ?? ?? ?? ?? 30 53 ff 83 7d ?? 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 2c 8a 8c 15 ?? ?? ?? ?? 30 08 40 83 7d 10 00 89 85 ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "4TvFPAD6TxMyX6zgXakbMQtQulYSTGmhqy4q" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 4e ff 8b 8d ?? ?? ?? ?? 4f 75}  //weight: 1, accuracy: Low
        $x_1_2 = "zswKNF4gnd10OtJkfSu5rcjlJFvrrlTcWxqwUCy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 9a 1e 00 00 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 4f}  //weight: 1, accuracy: Low
        $x_1_2 = "3UVoZP1MhvJpXtWhXvbOB5HrW2MuN0iWH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 44 24 ?? 83 c0 01 89 44 24 ?? 8a 54 14 ?? 30 50 ff 83 bc 24 ?? ?? 00 00 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = "LlLRNM?PPvEzd{drWlwS?9g~XbPcbB1~oK9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_MX_2147753739_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MX!MTB"
        threat_id = "2147753739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 14 5b 53 51 48 8b c6 48 ff c6 48 8b 0f 48 8b 00 48 33 c8 58 88 0f 48 ff c7 48 ff cb 48 8b c8 75}  //weight: 1, accuracy: High
        $x_1_2 = "Sleep" ascii //weight: 1
        $x_1_3 = "templ.dll" ascii //weight: 1
        $x_1_4 = "FreeBuffer" ascii //weight: 1
        $x_1_5 = "Release" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 8b 4d ?? 8b 55 ?? 03 c1 8a 14 32 30 10 41 3b 4d ?? 89 4d ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 18 f6 d0 88 45 ?? 3b d9 73 ?? eb ?? 8a 45 ?? 8a cb 2a 4d ?? 32 0b 32 c8 88 0b 03 df 85 f6 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 33 c9 f7 35 ?? ?? ?? ?? 33 c0 8b 44 24 ?? 8a 0c 38 8a 14 32 32 ca 88 0c 38 8b 4c 24 ?? 40 3b c1 89 44 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 0f b6 04 37 89 55 ?? 0f b6 d3 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 32 30 01 ff 45 ?? 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8b 08 8b 55 ?? 8b 02 8b 55 ?? 8b 75 ?? 8a 0c 0a 32 0c 06 8b 55 ?? 8b 02 8b 55 ?? 88 0c 02 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 0c 8a 0c 32 f6 d1 8b c6 3b f7 73 ?? 8a d0 2a d3 32 10 32 d1 88 10 03 45 ?? 3b c7 72 ?? 46 ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 08 8b 55 ?? 8b 02 8b 55 ?? 0f b6 04 02 8b 55 ?? 0f b6 0c 0a 33 c8 8b 55 ?? 8b 02 8b 55 ?? 88 0c 02 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 32 f6 d1 8b c6 3b f7 73 ?? 8a d0 2a d3 32 10 32 d1 88 10 03 45 ?? 3b c7 72 ?? 8b 55 ?? 46 ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3b df 7e ?? 8b 4c 24 ?? 8d 4c 19 ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c3 7c ?? 8d 43 01 c6 83 ?? ?? ?? ?? 00 83 f8 3e 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fa 8a 04 0f 88 04 0e 88 1c 0f 0f b6 04 0e 0f b6 d3 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 ?? 8a 14 0a 30 54 28 ?? 3b 6c 24 1c 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 0f b6 04 37 03 c1 f7 35 ?? ?? ?? ?? 8b da ff 15 ?? ?? ?? ?? 8b 45 ?? 8b 4d ?? 8a 14 33 03 c1 30 10 41 3b 4d ?? 89 4d ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 02 f6 d1 3b c6 73 ?? 8a d0 2a 55 ?? 32 10 32 d1 88 10 03 c7 3b c6 72 ?? 8b 45 ?? 40 ff 4d ?? 89 45 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0a f6 d0 88 45 ?? 8b d9 3b 4d ?? 73 ?? eb ?? 8a 45 ?? 8a cb 2a 4d ?? be 23 00 00 00 32 0b 32 c8 88 0b 6a 14 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 32 f6 d1 8b c6 3b f7 73 ?? eb ?? 8d 49 00 8a d0 2a d3 32 10 32 d1 88 10 03 45 ?? 3b c7 72 ?? 8b 55 ?? 46 ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 b9 14 02 00 00 f7 f9 8a 5d 00 8b 44 24 ?? 83 c0 f0 c7 84 24 ?? ?? ?? ?? ff ff ff ff 8d 48 ?? 8a 54 14 18 32 da 88 5d 00 45 83 ca ff f0 0f c1 11 4a 85 d2 7f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 35 ?? ?? ?? ?? 89 55 ?? 8b 45 ?? 8b 08 8b 55 ?? 8b 02 8b 55 ?? 8b 75 ?? 8a 0c 0a 32 0c 06 8b 55 ?? 8b 02 8b 55 ?? 88 0c 02 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 2f 88 04 3b 88 0c 2f 0f b6 04 3b 0f b6 c9 03 c1 33 d2 f7 35 ?? ?? ?? ?? 89 54 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 3a 30 14 08 8b 4c 24 ?? 40 3b c1 89 44 24 ?? 0f 82 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f bf fa 3b bd ?? ?? ?? ?? 7f ?? 8b 41 ?? 8b 51 ?? 2b c2 33 d2 8a 14 38 03 c7 89 85 ?? ?? ?? ?? 8b 45 ?? 8a 14 02 8b 85 ?? ?? ?? ?? 88 10 8b 85 ?? ?? ?? ?? 03 f8 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 40 f7 d9 8a 4c 0a ?? 88 88 ?? ?? ?? ?? eb ?? c6 83 ?? ?? ?? ?? 00 43 83 fb 3d 7f ?? c6 83 ?? ?? ?? ?? 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "qbwC+<F$z@Iv3p_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 04 37 81 e1 ff 00 00 00 03 c1 f7 35 ?? ?? ?? ?? 89 54 24 ?? ff 15 ?? ?? ?? ?? 8b 54 24 ?? 8b 44 24 ?? 8a 0c 32 8a 14 28 32 d1 88 14 28 8b 44 24 ?? 45 3b e8 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 f7 35 ?? ?? ?? ?? 8b ea ff 15 ?? ?? ?? ?? 85 c0 74 ?? ff 15 ?? ?? ?? ?? 8a 14 2e 8b 44 24 ?? 8b 6c 24 ?? 8a 0c 28 32 ca 88 0c 28 8b 4c 24 ?? 40 3b c1 89 44 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fa 8b 54 24 ?? 81 e2 ff 00 00 00 8a 04 0f 88 04 0e 33 c0 88 1c 0f 8a 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 ?? 8a 1c 28 8a 14 0a 32 da 88 1c 28 8b 44 24 ?? 45 3b e8 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_22
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3b df 7e ?? 8b 4c 24 ?? 8d 4c 19 ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c3 7c ?? 8d 43 ?? c6 83 ?? ?? ?? ?? 00 83 f8 3e 7d}  //weight: 1, accuracy: Low
        $x_1_2 = "1C$IyqzH*QM9vHL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_23
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3b df 7e ?? 8b 4c 24 ?? 8d 4c 19 ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c3 7c ?? 8d 43 ?? c6 83 ?? ?? ?? ?? 00 83 f8 3e 7d}  //weight: 1, accuracy: Low
        $x_1_2 = "RCrBKco!#boDL0D" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_24
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 11 99 f7 fb 8d 45 ?? 50 8b da ff 15 ?? ?? ?? ?? 8a 0c 30 32 d9 8d 4d ?? 51 ff 15 ?? ?? ?? ?? 8d 4d ?? 88 1c 30 ff 15 ?? ?? ?? ?? 8b 4d ?? 8b 1d ?? ?? ?? ?? b8 01 00 00 00 03 c8 89 4d ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_25
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 f1 8b 45 ?? 89 55 ?? 8d 0c 1a 8a 14 1a 88 14 18 8a 55 ?? 88 11 0f b6 04 18 0f b6 ca 03 c1 33 d2 f7 35 ?? ?? ?? ?? 89 55}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c1 8a 14 1a 30 10 41 3b 4d ?? 89 4d ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_26
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 81 fb 00 01 00 00 72 ?? ff 15 ?? ?? ?? ?? 8b 0f 8b 51 ?? 8b 4d ?? 8a 04 32 8b 75 ?? 88 04 19 b8 01 00 00 00 03 c3 0f 80 ?? ?? ?? ?? 8b d8 eb ?? 8b 17 52 6a 01 ff 15 ?? ?? ?? ?? 66 83 c6 02 89 85 ?? ?? ?? ?? 0f 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_27
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 33 f6 d0 8b ce 3b f7 73 ?? eb ?? 8d 49 00 8a d9 2a da 32 19 32 d8 88 19 03 4d ?? 3b cf 72 ?? 8b 5d ?? 46 ff 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = "EFoqekkkBCegArbgrmGrmgtGGmka" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_28
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 8b f0 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b cb 89 45 ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 33 db 53 6a 01 53 89 45 ?? 53 8d 45 ?? 50 89 5d ?? ff d6 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_2 = "ESET hyunya" ascii //weight: 1
        $x_1_3 = "H$I<JREJ+w1#M+H" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_29
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 11 99 f7 fb 8d 45 ?? 50 8b da ff 15 ?? ?? ?? ?? 8b 4e ?? 8b 56 ?? 2b ca 8a 14 08 32 da 8d 55 ?? 52 ff 15 ?? ?? ?? ?? 8b 4e ?? 8b 56 ?? 2b ca 88 1c 08 8d 4d ?? ff 15 ?? ?? ?? ?? 8b 4d ?? 8b 1d ?? ?? ?? ?? b8 01 00 00 00 03 c8 8b 45 ?? 89 4d ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_30
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 8d 45 ?? 89 5d ?? 50 53 ff 75 ?? 6a 4c 68 ?? ?? ?? ?? ff 75 ?? e8 ?? ?? ?? ?? 85 c0 5f 74 ?? 8b 45 ?? ff 30 50 ff 75 ?? 53 6a 01 53 ff 75 ?? e8 ?? ?? ?? ?? 85 c0 0f 95 c0 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "i9j21?tGOV)RwAp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_31
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 81 fb 00 01 00 00 72 ?? ff 15 ?? ?? ?? ?? 8b 07 8b 48 ?? 8b 45 ?? 8a 14 31 8b 75 ?? 88 14 18 b8 01 00 00 00 03 c3 0f 80 ?? ?? ?? ?? 8b d8 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {0f bf c9 3b 4d ?? 7f ?? 8b 16 8b 42 ?? 8b 7a ?? 2b c7 33 d2 8a 14 08 8d 3c 08 8b 45 ?? 8a 14 02 8b 45 ?? 88 17 03 c8 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_32
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 01 8a 14 37 88 04 37 88 11 49 47 3b 7d 08 7e}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 59 75 ?? 8b 45 ?? 0f b7 00 8b 3c 83 03 7d ?? ff 45 ?? 83 45 ?? 04 8b 45 ?? 83 45 ?? 02 3b 46 ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = "Stupid windows defender" ascii //weight: 1
        $x_1_4 = "amuNxEcollAlautriV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GKM_2147753743_33
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GKM!MTB"
        threat_id = "2147753743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 33 f6 d0 8b ce 3b f7 73 ?? eb ?? 8d 49 00 8a d9 2a da 32 19 32 d8 88 19 03 4d ?? 3b cf 72 ?? 8b 5d ?? 46 ff 4d ?? 75}  //weight: 2, accuracy: Low
        $x_1_2 = "QMSVMIFTOITAMAITEQJBKQNGSPHVVQCJSKGMSDFFJHOVJ" ascii //weight: 1
        $x_1_3 = "LGQQWYPJBTGESFQTXUJKOXIZYDIVDNAUCECOMV" ascii //weight: 1
        $x_1_4 = "faqxszurbvyfwocwnyrvlsbpuhxbhtfacyaznrptsjb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_ZZ_2147753822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ZZ!ST"
        threat_id = "2147753822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "ST: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 f2 ff 00 00 89 45 04 59 8b d7 49 8b f2 49 05 00 05}  //weight: 2, accuracy: Low
        $x_2_2 = {e8 00 00 00 00 58 89 c3 05 3a 05 00 00 81 c3 ?? ?? ?? ?? 68 01 00 00 00 68 05 00 00 00 53 68 45 77 62 30 50 e8 04 00 00 00 83 c4 14 c3 83 ec 48 83 64 24 18 00 b9 4c 77 26 07}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 74 24 10 8b 44 16 24 8d 04 58 0f b7 0c 10 8b 44 16 1c 8d 04 88 8b 04 10 03 c2 eb db 4d 5a 80}  //weight: 1, accuracy: High
        $x_1_4 = {8d 40 00 00 00 00 [0-32] 05 8b ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_DHI_2147753913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHI!MTB"
        threat_id = "2147753913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d5 33 d2 8b c6 b9 [0-4] f7 f1 8a 04 3e 8a 14 1a 32 c2 88 04 3e 8b 44 24 [0-4] 46 3b f0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DHJ_2147753923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHJ!MTB"
        threat_id = "2147753923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 79 70 74 45 6e 63 72 79 70 74 [0-6] 43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 [0-6] 43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 57}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 73 6f 75 72 63 65 [0-10] 52 65 73 6f 75 72 63 65 [0-6] 4c 6f 61 64 52 65 73 6f 75 72 63 65 [0-6] 46 69 6e 64 52 65 73 6f 75 72 63 65 41}  //weight: 1, accuracy: Low
        $x_1_3 = "amuNxEcollAlautriV" ascii //weight: 1
        $x_1_4 = "VirtualAllocExNuma" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Trickbot_MXI_2147754277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MXI!MTB"
        threat_id = "2147754277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 00 01 00 00 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d 0c 89 45 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_VC_2147754698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.VC!MTB"
        threat_id = "2147754698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 8c 15 ?? ?? ?? ?? 0f b6 c3 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 4e ?? 8b 8d ?? ?? ?? ?? 4f}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 1c 38 30 19 03 ce 03 fe 3b ca 83 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_PVH_2147754721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PVH!MTB"
        threat_id = "2147754721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 30 84 0d ?? d1 ff ff 50 53 08 00 0f b6 84 ?? ?? fe ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "6POXKEEVQ38SDJ4VY45" ascii //weight: 1
        $x_1_3 = "BBWYNRCG1C35PLRX2W6" ascii //weight: 1
        $x_1_4 = "5P1DHC2Q4AXCK1WGPMZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_DHK_2147754788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHK!MTB"
        threat_id = "2147754788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 33 d2 b9 ?? ?? ?? ?? f7 f1 8b ca [0-50] 03 c1 99 b9 00 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 4e ff}  //weight: 1, accuracy: Low
        $x_1_2 = "ubcv4m46cyAWtOPFJ8dsHDmyjNZduBj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_PVM_2147754945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PVM!MTB"
        threat_id = "2147754945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 5e 3e 03 c2 80 e2 80 32 d3 8a 18 32 da 88 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PVI_2147755420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PVI!MTB"
        threat_id = "2147755420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 53 56 57 50 53}  //weight: 2, accuracy: Low
        $x_2_2 = {58 5b 6a 04 68 00 30 00 00 68 00 e1 f5 05 6a 00 ff 15 ?? ?? ?? ?? 8b c8 50 53}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PVJ_2147755421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PVJ!MTB"
        threat_id = "2147755421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 53 56 50 53}  //weight: 2, accuracy: Low
        $x_1_2 = {50 ff d6 89 45 fc 50 53 18 00 58 5b 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 35}  //weight: 1, accuracy: Low
        $x_2_3 = {55 8b ec b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 53 c7 45 dc ?? ?? ?? ?? c7 45 d4 00 00 00 00 c7 45 d8 ?? ?? ?? ?? c7 45 f4 00 00 00 00 c7 45 f0 00 00 00 00 50 53}  //weight: 2, accuracy: Low
        $x_1_4 = {58 5b 6a 04 68 00 30 00 00 68 00 e1 f5 05 6a 00 ff 15 ?? ?? ?? ?? 89 45 f0 50 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_DHL_2147755512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHL!MTB"
        threat_id = "2147755512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 84 35 b8 e5 ff ff 0f b6 c9 03 c1 99 b9 42 1a 00 00 f7 f9 0f b6 94 15 b8 e5 ff ff 30 53 ff 83 7d 0c 00 75 9b}  //weight: 1, accuracy: High
        $x_1_2 = "OwcRJEC2g5NJ9wbOmJnUO5nK1LWXpbbndxlN4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_RLK_2147755526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RLK!MTB"
        threat_id = "2147755526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 03 4d e4 8d 14 33 33 c1 33 c2 6a 00 2b f8 81 c3 47 86 c8 61 ff 15 ?? ?? ?? ?? ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RA_2147755643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RA!MTB"
        threat_id = "2147755643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 84 05 c0 f6 ff ff 40 3b c6 72}  //weight: 1, accuracy: High
        $x_1_2 = {8a 8c 15 c0 f6 ff ff 30 08 40 83 [0-31] 0f 2f 00 0f b6 07 [0-10] 99 [0-10] f7 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MS_2147755658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MS!MTB"
        threat_id = "2147755658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 89 45 ?? 68 00 04 00 00 8d 85 ?? ?? ?? ?? 50 6a 00 ff ?? ?? c7 45 b4 ?? ?? ?? ?? 6a 01 8b 4d ?? 51 8d 95 ?? ?? ?? ?? 52 ff ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "MOfH?6M42F252loLt0N~7?COsSwyith8HYnnP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PVL_2147755673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PVL!MTB"
        threat_id = "2147755673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 53}  //weight: 2, accuracy: Low
        $x_2_2 = {58 5b 6a 04 68 00 30 00 00 68 00 e1 f5 05 6a 00 ff 15 ?? ?? ?? ?? 89 45 e4 50 53}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DHN_2147755897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHN!MTB"
        threat_id = "2147755897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c3 03 c1 99 b9 9d 15 00 00 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "2SubaWAaRzfGeY9mW2gThA7TDyNpVLzf6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_DL_2147756290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DL!MTB"
        threat_id = "2147756290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "w0hLcWXOF0pxUBtZtJdBTwT5UBE8XGcHbQbrOB" ascii //weight: 3
        $x_3_2 = "WMz3ZyKJs6YfAIyvSdcZSRsGBCkqNOo0kAec" ascii //weight: 3
        $x_1_3 = "dllhost.exe" ascii //weight: 1
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_DSA_2147756470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DSA!MTB"
        threat_id = "2147756470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec b8 18 2c 00 00 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 c5 89 45 fc c6 85 fc d3 ff ff ?? c6 85 fd d3 ff ff ?? c6 85 fe d3 ff ff ?? c6 85 ff d3 ff ff ?? c6 85 00 d4 ff ff ?? c6 85 01 d4 ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_PVB_2147756471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PVB!MTB"
        threat_id = "2147756471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 83 ec 3c c7 45 ec ?? ?? ?? ?? c7 45 fc 00 00 00 00 eb ?? 8b 45 fc 83 c0 01 89 45 fc 81 7d fc ff 2b 00 00 0f 8d ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 83 ec 18 c7 45 fc 00 00 00 00 c7 45 ec 00 00 00 00 c7 45 f0 ?? ?? ?? ?? c7 45 fc 00 00 00 00 eb ?? 8b 45 fc 83 c0 01 89 45 fc 81 7d fc ff 2b 00 00 0f 8d ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_DSB_2147756525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DSB!MTB"
        threat_id = "2147756525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 33 d2 b9 03 00 00 00 f7 f1 8b 45 f0 0f be 0c 10 8b 55 fc 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d fc 88 81 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = "14BEFAWKU1XCQMIYMOF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_SH_2147756598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SH"
        threat_id = "2147756598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 70 28 ff 70 24 ff 70 20 ff 70 1c ff 70 18 ff 70 14 ff 70 10 ff 70 0c ff 70 08 ff 10}  //weight: 1, accuracy: High
        $x_1_2 = {ff 76 04 ff 36 ff 56 0c ff 76 04 ff 56 14 ff 36 ff 56 14 89 7e 04 89 3e 57 ff 56 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DSC_2147756797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DSC!MTB"
        threat_id = "2147756797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 19 84 db 74 ?? 8a fb 80 c7 bf 80 ff 19 77 ?? 8a fb 80 f3 20 80 e7 20 0a df 88 19 4a 41 48 3b d6 7f}  //weight: 1, accuracy: Low
        $x_1_2 = "ZXpMZX4S+r8pPYVOPX8pnBq0ZXG4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DHO_2147756892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHO!MTB"
        threat_id = "2147756892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 53 8d 34 07 ff 15 ?? ?? ?? ?? 59 33 d2 8b c8 8b c7 f7 f1 8a 04 53 30 06 [0-4] 3b 7c 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_STZ_2147757064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.STZ"
        threat_id = "2147757064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 30 00 00 [0-16] ff d0 50 ff 15 ?? ?? ?? 10}  //weight: 1, accuracy: Low
        $x_1_2 = "An0qTGEr" ascii //weight: 1
        $x_1_3 = "4TvFPAD6TxMyX6zgXakbMQtQulYSTGmhqy4q" ascii //weight: 1
        $x_1_4 = "VirtualAllocExNuma" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_STX_2147757065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.STX"
        threat_id = "2147757065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 0a 68 46 82 00 00 6a 00 8b f8 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = "dz67jXhR" ascii //weight: 1
        $x_1_3 = "FrJXWXznAmP2y6Yj0heRR2iDimPE8Wd7zaCulWx46h5Jg" ascii //weight: 1
        $x_1_4 = "VirtualAllocExNuma" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_NBM_2147757074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.NBM!ST"
        threat_id = "2147757074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "ST: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 89 c3 05 3a 05 00 00 81 c3 ?? ?? ?? ?? 68 01 00 00 00 68 05 00 00 00 53 68 45 77 62 30 50 e8 04 00 00 00 83 c4 14 c3 83 ec 48 83 64 24 18 00 b9 4c 77 26 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DHP_2147757566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHP!MTB"
        threat_id = "2147757566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 84 35 ?? ?? ?? ?? 81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 83 c4 0c 8a 94 15 00 32 c2 88 03}  //weight: 1, accuracy: Low
        $x_1_2 = "MCdM1Aw|2SaG2rdGzyI3U7$K%vetuiV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_DSE_2147757620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DSE!MTB"
        threat_id = "2147757620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 84 24 90 02 00 00 0f b6 cb 8a 1c 07 8a 54 0c 1c 32 da 88 1c 07 8b 84 24 94 02 00 00 47 3b f8 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DSF_2147758117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DSF!MTB"
        threat_id = "2147758117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 33 d2 b9 0c 00 00 00 f7 f1 8b 45 e8 0f be 0c 10 8b 55 f4 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d f4 88 81 ?? ?? ?? ?? 81 7d f4 04 2c 00 00 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DSG_2147758452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DSG!MTB"
        threat_id = "2147758452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 33 d2 b9 0c 00 00 00 f7 f1 8b 45 e8 0f be 0c 10 8b 55 f4 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d f4 88 81 ?? ?? ?? ?? 81 7d f4 04 2a 00 00 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DSH_2147758649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DSH!MTB"
        threat_id = "2147758649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 e4 d5 ff ff 33 d2 b9 [0-4] f7 f1 8b 45 f8 0f be 0c 10 8b 95 e4 d5 ff ff 0f b6 84 15 e8 d5 ff ff 33 c1 8b 8d e4 d5 ff ff 88 84 0d e8 d5 ff ff 81 bd e4 d5 ff ff 04 2a 00 00 73 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AR_2147758688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AR!MTB"
        threat_id = "2147758688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b7 c1 0f b7 0f 8d 70 bf 66 83 fe 19 77 03 83 c0 20 8d 71 bf 66 83 fe 19 77 03 83 c1 20 66 3b c1}  //weight: 5, accuracy: High
        $x_5_2 = {8b 34 b2 8b 45 08 03 f1 8a 1e 3a 18 75 18 84 db 74 10 8a 5e 01}  //weight: 5, accuracy: High
        $x_5_3 = {8b 44 24 14 8d 0c 03 8b 44 24 1c 88 1c 08 8b c3 99 f7 7d 14 8b 45 10 43 8a 04 02 88 01 3b de}  //weight: 5, accuracy: High
        $x_10_4 = "c:\\Users\\Mr.Anderson\\Documents\\Visual Studio 2008\\Projects\\Anderson\\Release\\Anderson.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_AR_2147758688_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AR!MTB"
        threat_id = "2147758688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "F:\\Projects\\WebInject\\bin\\x86\\Release_logged\\webinject32.pdb" ascii //weight: 10
        $x_10_2 = "F:\\Projects\\WebInject\\bin\\x64\\Release_logged\\webinject64.pdb" ascii //weight: 10
        $x_10_3 = "webinject64.dll" ascii //weight: 10
        $x_10_4 = "webinject32.dll" ascii //weight: 10
        $x_5_5 = "bRS8yYQ0APq9xfzC" ascii //weight: 5
        $x_5_6 = "ESTR_PASS_" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_DSI_2147758757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DSI!MTB"
        threat_id = "2147758757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f1 8b 45 ?? 0f be 0c 10 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d ?? 88 81 ?? ?? ?? ?? 81 7d ?? 04 2a 00 00 73 0a 00 8b 45 ?? 33 d2 b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DSJ_2147758758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DSJ!MTB"
        threat_id = "2147758758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f1 8b 85 ?? ?? ?? ?? 0f be 0c 10 8b 55 ?? 0f b6 84 15 ?? ?? ?? ?? 33 c1 8b 4d ?? 88 84 0d ?? ?? ?? ?? 81 7d ?? 04 2a 00 00 73 0a 00 8b 45 ?? 33 d2 b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EM_2147759496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EM!MTB"
        threat_id = "2147759496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 08 00 00 00 6b c2 00 8b 4d fc 8b 55 f4 8b 49 24 2b 0c 02 03 4d fc 89 4d d8 ba 08 00 00 00 6b c2 00 8b 4d fc 8b 55 f4 8b 49 1c 2b 0c 02 03 4d fc 89 4d d4 ba 08 00 00 00 6b c2 00 8b 4d fc 8b 55 f4 8b 49 20 2b 0c 02 03 4d fc 89 4d e0 c7 45 ec 00 00 00 00 8b 55 fc 8b 42 18 89 45 f0 8b 4d f0 d1 e9 89 4d f8 8b 55 f0 83 c2 01 89 55 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EM_2147759496_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EM!MTB"
        threat_id = "2147759496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be c8 81 e1 ?? ?? ?? ?? 8b c1 c1 e8 03 83 e1 07 8d 14 30 b0 01 d2 e0 8d 7f 01 08 02 8a 07 84 c0 75 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AVI_2147759665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AVI!MSR"
        threat_id = "2147759665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chqiTrZqioQ9WfpJCEZkZxBFjbAnrezsEXgZFUWB" ascii //weight: 1
        $x_1_2 = "sdkdiff\\Win32\\Release\\sdkdiff.pdb" ascii //weight: 1
        $x_1_3 = "sdkdiff.exe" ascii //weight: 1
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
        $x_1_5 = "CLSID\\{ADB880A6-D8FF-11CF-9377-00AA003B7A11}\\InprocServer32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_NI_2147759923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.NI!MSR"
        threat_id = "2147759923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ForceRemove {9AEC2879-1A82-4FEA-AA4F-60B98D3AC293} = s 'Sample Spell Checking Provider'" ascii //weight: 1
        $x_1_2 = "SampleSpellingProvider.dll" ascii //weight: 1
        $x_1_3 = "DllCanUnloadNow" ascii //weight: 1
        $x_1_4 = "DllGetClassObject" ascii //weight: 1
        $x_1_5 = "DllRegisterServer" ascii //weight: 1
        $x_1_6 = "DllUnregisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_VP_2147760013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.VP!MSR"
        threat_id = "2147760013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "frmSplines" ascii //weight: 1
        $x_1_2 = "modSplines" ascii //weight: 1
        $x_1_3 = "frmCopyright" ascii //weight: 1
        $x_1_4 = "frmIstruzioni" ascii //weight: 1
        $x_1_5 = "Splines" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RB1_2147760016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RB1!MTB"
        threat_id = "2147760016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 53 57 8b ?? ?? ?? 8b ?? ?? 8b ?? 8b ?? ?? 83 ?? ?? c1 ?? ?? 8b ?? 2b ?? f7 ?? 8b ?? 89 ?? ?? 8b ?? ?? ?? 8b ?? 2b ?? 89 ?? ?? 76 ?? 33 ?? 33 ?? 46 81 ?? ?? ?? ?? ?? 7f ?? 8a ?? ?? 03 ?? 30 ?? 03 ?? eb ?? 33 ?? 3b ?? 72 ?? 5f 5b 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DHQ_2147760232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHQ!MTB"
        threat_id = "2147760232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 40 89 85 01 0f b6 94 15 ?? ?? ?? ?? 30 50 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "IZxRiP8o0flkPQesvqX2jioOd8CR2V" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_PSB_2147760438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PSB!MTB"
        threat_id = "2147760438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 05 8a 4d 0f 00 30 4c 05 ?? 40 83 f8 ?? ?? ?? ?? ?? ?? eb f1}  //weight: 10, accuracy: Low
        $x_1_2 = {41 83 f9 09 73 05 8a 0e 00 8d 04 ?? 30 44 0d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb ee}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 04 0a 30 44 0d ?? 41 83 f9 ?? 73 05 8a 55 ?? eb ee 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 04 0b 30 44 0d ?? 41 83 f9 ?? 73 05 8a 55 ?? eb ee 8d}  //weight: 1, accuracy: Low
        $x_10_5 = "IsDebuggerPresent" ascii //weight: 10
        $x_10_6 = "FlushFileBuffers" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_DHR_2147760665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHR!MTB"
        threat_id = "2147760665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 18 8b b4 24 ?? ?? ?? ?? 8a 04 31 8a 54 14 1c 32 c2 88 04 31}  //weight: 1, accuracy: Low
        $x_1_2 = "43I2s1UfEx9IihpOp25rTODaBRkdTu~rQzNJAGl5V" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_MB_2147761209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MB!MTB"
        threat_id = "2147761209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c1 f7 f7 8a 5c 0c ?? 0f b6 c3 41 0f b6 14 2a 03 d6 03 c2 33 d2 be ?? ?? ?? ?? f7 f6 8b f2 8a 44 34 ?? 88 44 0c ?? 88 5c 34 ?? 81 f9 01 72 cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_DHS_2147761342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHS!MTB"
        threat_id = "2147761342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c3 03 c1 b9 15 e0 00 00 99 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 4f ff}  //weight: 1, accuracy: Low
        $x_1_2 = "tRYQigaa0rjaoM2Lb4aO1iGSDrFLvP0ALFHN0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_DHT_2147761506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.DHT!MTB"
        threat_id = "2147761506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 44 24 18 83 c4 08 8a 54 14 14 32 da 88 5d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "1%OB{xLuJ}O$d~Cd#vT}Pmd~rW5$?0JR2U1hq0Z1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_RAS_2147762230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RAS!MTB"
        threat_id = "2147762230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 ca 00 ff ff ff 42 8a 4c 14 ?? 8b 54 24 ?? 8a 1c 3a 8b 44 24 ?? 32 cb 88 0f 47 48 89 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AV_2147763196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AV!MSR"
        threat_id = "2147763196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 18 0f b6 04 0f 0f b6 d2 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 8b 54 24 1c 32 04 13 8b 54 24 2c 88 04 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_ART_2147763648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ART!MTB"
        threat_id = "2147763648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "53436362122267559494412189236696689639154869969443412549771529119795857234339776824541675272999599565967557664832379734" wide //weight: 1
        $x_1_2 = "22267559494412189236696689639154869969443412549771529119795857234339776824541675272999599565967557664832379734" wide //weight: 1
        $x_1_3 = "AC:\\Users\\911\\Desktop\\mp3_sharebox_0\\Developing\\Visual Basic Projects\\MP3 ShareBox\\MP3 ShareBox.vbp" wide //weight: 1
        $x_1_4 = "\\AD:\\mp3_sharebox_0\\Developing\\Visual Basic Projects\\MP3 ShareBox\\MP3 ShareBox.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Trickbot_PD_2147766621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PD"
        threat_id = "2147766621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_9_1 = {33 db c6 45 ?? 66 c6 45 ?? 73 c6 45 ?? 79 c6 45 ?? 57 c6 45 ?? 6a}  //weight: 9, accuracy: Low
        $x_9_2 = {83 f0 67 88 44 24 ?? 8a 44 24 ?? c7 84 24 ?? 00 00 00 04 00 00 00 c6 84 24 ?? 00 00 00 41 c6 84 24 ?? 00 00 00 76 c6 84 24 ?? 00 00 00 76 c6 84 24 ?? 00 00 00 6b c6 84 24 ?? 00 00 00 76 c6 84 24 ?? 00 00 00 4d}  //weight: 9, accuracy: Low
        $x_1_3 = {43 a1 44 a1 45 a1 46 a1 47 a1 48 a1 49 a1 4a a1 4d a1 4e a1 50 a1 51 a1 52 a1 53 a1 54 a1 55 a1 43 9d 43 9d}  //weight: 1, accuracy: High
        $x_1_4 = {c4 a2 c5 a2 c6 a2 c7 a2 c8 a2 c9 a2 d2 a2}  //weight: 1, accuracy: High
        $x_1_5 = {06 a3 04 a3 05 a3 08 a3 03 a3 0d a3 0c a3 0e a3 4b 9d 4e 9d 50 9d 53 9d 56 9d 58 9d 84 9d}  //weight: 1, accuracy: High
        $x_1_6 = {8a 10 0f be 37 0f be ca 33 ce 88 08 40}  //weight: 1, accuracy: High
        $x_1_7 = {8a 04 0a 0f be c0 83 e8 ?? 88 04 0a 42 83 fa}  //weight: 1, accuracy: Low
        $x_1_8 = {8a 04 0a 0f be c0 48 88 04 0a 42 83 fa}  //weight: 1, accuracy: High
        $x_1_9 = {8a 10 0f be 37 0f be ca 33 ce 88 08 40 83 ed 01}  //weight: 1, accuracy: High
        $x_1_10 = {68 3f 00 0f 00 6a 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_11 = {68 0c 28 22 00}  //weight: 1, accuracy: High
        $x_1_12 = {68 14 28 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_9_*) and 1 of ($x_1_*))) or
            ((2 of ($x_9_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_ZZ_2147766670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ZZ"
        threat_id = "2147766670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 68 1e 03 00 00 59 50 e2 fd 8b c7 57 8b ec 05 f9 24 00 00 89 45 04 8b c6 89 45 20 68 f0 ff 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_ZZ_2147766670_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ZZ"
        threat_id = "2147766670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 43 6f 6e 74 72 6f 6c 40 33 36 00 5f 46 72 65 65 42 75 66 66 65 72 40 34 00 5f 52 65 6c 65 61 73 65 40 34 00 5f 53 74 61 72 74 40 33 32 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 61 63 6b 77 61 72 64 00 43 6f 6e 74 72 6f 6c 00 46 6f 72 77 61 72 64 00 46 72 65 65 42 75 66 66 65 72 00 50 61 75 73 65 00 52 65 6c 65 61 73 65 00 52 65 76 65 72 73 65 00 53 68 75 66 66 6c 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 6f 6e 74 72 6f 6c 00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 6f 6e 74 72 6f 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 46 72 65 65 42 75 66 66 65 72 00 4a 4e 49 5f 4f 6e 4c 6f 61 64 00 4a 4e 49 5f 4f 6e 55 6e 6c 6f 61 64 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 49 6e 69 74 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00 55 6e 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 4a 52 45 5f 4f 6e 4c 6f 61 64 00 4a 52 45 5f 4f 6e 55 6e 6c 6f 61 64 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 4d 6f 76 65 33 44 00 4d 6f 76 65 42 6f 74 74 6f 6d 00 4d 6f 76 65 4c 65 66 74 00 4d 6f 76 65 52 69 67 68 74 00 4d 6f 76 65 54 6f 70 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 4e 65 74 53 65 72 76 65 72 53 74 61 72 74 00 4e 65 74 53 65 72 76 65 72 53 74 6f 70 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 4f 6e 4c 6f 61 64 00 4f 6e 55 6e 6c 6f 61 64 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_10 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_11 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_12 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 3f 52 65 6c 65 61 73 65 41 40 [0-32] 00 53 74 61 72 74 00}  //weight: 1, accuracy: Low
        $x_1_13 = {43 6f 6e 74 72 6f 6c 00 3f 44 4c 4c 43 6f 6e 74 72 6f 6c 40 [0-64] 00 3f 44 4c 4c 46 72 65 65 42 75 66 66 65 72 40 [0-16] 00 3f 44 4c 4c 52 65 6c 65 61 73 65 40 [0-16] 00 3f 44 4c 4c 53 74 61 72 74 40 [0-64] 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_ZY_2147766672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ZY"
        threat_id = "2147766672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 3b 45 f8 73 25 8b 45 0c 0f b6 00 66 0f be d0 8b 45 fc 66 89 10 8b 45 0c 0f b6 00 84 c0 74 0a 83 45 fc 02 83 45 0c 01 eb d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_ZB_2147766676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ZB"
        threat_id = "2147766676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Grabber attempt." ascii //weight: 2
        $x_2_2 = "Could not gather browser data" ascii //weight: 2
        $x_2_3 = "grabber_temp.edb" ascii //weight: 2
        $x_3_4 = {2e 64 6c 6c 00 43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_STM_2147766681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.STM"
        threat_id = "2147766681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MailClient.dll" ascii //weight: 1
        $x_1_2 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72}  //weight: 1, accuracy: High
        $x_1_3 = "Injected process pid" ascii //weight: 1
        $x_1_4 = "WebInject build" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_STN_2147766683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.STN"
        threat_id = "2147766683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "temp\\webinject.log" ascii //weight: 1
        $x_1_2 = "RemoveFFHooks" ascii //weight: 1
        $x_1_3 = "Injected process pid" ascii //weight: 1
        $x_1_4 = "WebInject build" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_STO_2147766685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.STO"
        threat_id = "2147766685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start CrawlerThread" ascii //weight: 1
        $x_1_2 = "temp\\owa.log" ascii //weight: 1
        $x_1_3 = "FindSubdomains()" ascii //weight: 1
        $x_1_4 = "ScanSend()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_STP_2147766687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.STP!dll"
        threat_id = "2147766687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NETWORKDLL" ascii //weight: 1
        $x_1_2 = "<moduleconfig><needinfo name" ascii //weight: 1
        $x_1_3 = "Grabber started" ascii //weight: 1
        $x_1_4 = "nltest /domain_trusts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_STQ_2147766689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.STQ!dll"
        threat_id = "2147766689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 57 8b f2 8b f9 33 d2 6a 7c 68 e6 b7 a2 2c 42 e8 0f 2a 00 00 59 59 85 c0 74 06 56 57 ff d0 eb 02}  //weight: 1, accuracy: High
        $x_1_2 = {b1 31 c7 85 ec fd ff ff 31 45 54 42 c7 85 f0 fd ff ff 45 6e 55 41 33 c0 c7 85 f4 fd ff ff 5e 42 45 00 30 8c 05 ed fd ff ff 40 83 f8 0a 73 08 8a 8d ec fd ff ff eb eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_STR_2147766691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.STR!dll"
        threat_id = "2147766691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "U29mdHdhcmVcTWljcm9zb2Z0XE9mZmljZVwxNS4wXE91dGxvb2tcUHJvZmlsZXNcT" ascii //weight: 1
        $x_1_2 = {03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_STS_2147766693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.STS!dll"
        threat_id = "2147766693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fd ff ff d1 af d2 11 8b d9 c7 85 fc fd ff ff 9c b9 00 00 50 89 9d 08 fe ff ff c7 85 00 fe ff ff f8 7a 36 9e c7 85 e4 fd ff ff 7f 32 b6 50 c7 85 e8 fd ff ff d1 af d2 11 c7 85 ec fd ff ff 9c b9 00 00 c7 85 f0 fd ff ff f8 7a 36 9e}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 bd 71 c6 45 be 18 c6 45 bf 4f c6 45 c0 28 c6 45 c1 7a c6 45 c2 04 c6 45 c3 14 c6 45 c4 39 c6 45 c5 52 c6 45 c6 79 c6 45 c7 38 c6 45 c8 05 c6 45 c9 52 c6 45 ca 21 c6 45 cb 45 c6 45 cc 42 c6 45 cd 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_STT_2147766695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.STT!dll"
        threat_id = "2147766695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/RFT3W6+cnGSseLiy94NBbKdDJOkgHxal0EZq7vUVujMIhm85Y2zroAt1XfwCpPQ" ascii //weight: 5
        $x_5_2 = "jZWJgE8ForThuMtCkySIDPs1wYnbRav5+3dViz9KQ6pme4q7OB0Hx/lA2XGULcfN" ascii //weight: 5
        $x_1_3 = "bA7mJ6ptg2" ascii //weight: 1
        $x_1_4 = "PlzqY8cAR0jA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_STU_2147766697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.STU!dll"
        threat_id = "2147766697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 6d 6f 64 75 6c 65 63 6f 6e 66 69 67 3e [0-4] 3c 6e 65 65 64 69 6e 66 6f 20 6e 61 6d 65 3d 22 69 64 22 2f 3e [0-4] 3c 61 75 74 6f 63 6f 6e 66 3e [0-4] 3c 63 6f 6e 66 20 63 74 6c 3d 22 73 72 76 22 20 66 69 6c 65 3d 22 73 72 76 22 20 70 65 72 69 6f 64 3d 22 36 30 22 2f 3e [0-4] 3c 2f 61 75 74 6f 63 6f 6e 66 3e [0-4] 3c 2f 6d 6f 64 75 6c 65 63 6f 6e 66 69 67 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AAA_2147766699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AAA"
        threat_id = "2147766699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 0a a0 c9 48 83 c3 20 80 0a a0 cd 48 3b de 80 0a a0 d0 75 ?? 80 0a a0 d2 48 8b 97 b0 01 00 00 80 0a a0 d9 4c 8b 87 c0 01 00 00 80 0a a0 e0 4c 2b c2 80 0a a0 e3 49 c1 f8 05 80 0a a0 e7 e8 ?? ?? ?? ?? 80 0a a0 ec 90 80 0a a0 ed 33 c0 80 0a a0 ef 48 89 87 b0 01 00 00 80 0a a0 f6 48 89 87 b8 01 00 00 80 0a a0 fd 48 89 87 c0 01 00 00 80 0a a1 04 48 8b cf}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 8f dc 01 00 00 85 c9 74 5b ff 75 f0 8b 97 e0 01 00 00 51 e8 ?? ?? ?? ?? 8b 8f e4 01 00 00 b8 93 24 49 92 2b 8f dc 01 00 00 83 c4 08 f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 c2}  //weight: 1, accuracy: Low
        $x_1_3 = {64 6c 6c 00 43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 ?? 65 00 53 74 61 72 74 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {70 50 61 72 65 6e 74 44 61 74 ?? 20 69 73 20 6e 75 6c 6c 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {53 74 61 72 74 28 29 20 63 61 6c 6c ?? 64 2c 20 6d 6f 64 75 6c 65 20 68 61 6e 64 6c 65 20 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 65 6c 65 61 73 65 28 29 20 63 61 6c 6c 65 ?? 2c 20 6d 6f 64 75 6c 65 20 68 61 6e 64 6c 65 20 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {43 6f 6e 74 72 6f 6c 28 29 20 2d 3e 20 64 70 6f 73 74 20 63 61 6c ?? 65 64 2c 20 6d 6f 64 75 6c 65 20 68 61 6e 64 6c 65 20 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {63 3a 5c 74 65 6d 70 5c 63 6f ?? 6b 69 65 73 2e 6c 6f 67 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_9 = {57 61 6e 74 52 65 6c 65 ?? 73 65 00 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Trickbot_V_2147766706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.V!ibt"
        threat_id = "2147766706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 62 c7 01 63 00 00 00 e8 67 09 ff ff 6a 01 6a 72 88 41 04 e8 5b 09 ff ff 6a 02 6a 6f 88 41 05 e8 4f 09 ff ff 6a 03 6a 77 88 41 06 e8 43 09 ff ff 6a 04 6a 73 88 41 07 e8 37 09 ff ff 6a 05 6a 65 88 41 08 e8 2b 09 ff ff 6a 06 6a 72 88 41 09 e8 1f 09 ff ff 88 41 0a c6 41 0b 00 8a 41 04 8b c1 c2 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {56 8b 75 08 83 c9 ff 85 f6 74 18 0f b6 02 33 c1 c1 e9 08 0f b6 c0 33 0c 85 18 6b 04 10 42 83 ee 01 75 e8 f7 d1 8b c1 5e 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {56 43 32 30 58 43 30 30 55 8b ec 83 ec 08 53 56 57 55 fc ff 75 10 e8 27 de fc ff 83 c4 04 8b 5d 0c 8b 45 08 f7 40 04 06 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Trickbot_PN_2147766717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.PN!MSR"
        threat_id = "2147766717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 30 83 eb 08 32 cd 83 45 10 08 88 0c 38 8a 4c 30 01 32 cd 88 4c 38 01 8a 4c 30 02 32 cd 88 4c 38 02 8a 4c 30 03 32 cd}  //weight: 1, accuracy: High
        $x_1_2 = "rdpscan.dll" ascii //weight: 1
        $x_1_3 = "rdpscan.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_B_2147766720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.B!ibt"
        threat_id = "2147766720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\webinject32.pdb" ascii //weight: 1
        $x_1_2 = "\\webinject62.pdb" ascii //weight: 1
        $x_1_3 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74}  //weight: 1, accuracy: High
        $x_1_4 = "WebInject build %s %s (%s) starting" ascii //weight: 1
        $x_1_5 = "STATIC FAKE rebuild=" ascii //weight: 1
        $x_1_6 = "Injection failure process pid =" ascii //weight: 1
        $x_1_7 = "CheckAndInjectExplorer(): CreateToolhelp32Snapshot():" ascii //weight: 1
        $x_1_8 = "Chrome is zombie" ascii //weight: 1
        $x_1_9 = "Starting and injecting chrome" ascii //weight: 1
        $x_1_10 = "[INJECT] inject_via_remotethread_wow64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Trickbot_SV_2147766737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.SV!MTB"
        threat_id = "2147766737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 81 ec ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 c5 89 45 fc c7 85 ?? ?? ff ff ?? 00 00 00 c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff ?? 53 c6 85 ?? ?? ff ff ?? 33 db c6 85 ?? ?? ff ff ?? 8b d3 56 c6 85 ?? ?? ff ff ?? 8a 85 ?? ?? ff ff 57 88 9d ?? ?? ff ff 8a 84 15 ?? ?? ff ff 0f be 8d ?? ?? ff ff 0f be c0 33 c1 88 84 15 ?? ?? ff ff 42 83 fa 0c 72}  //weight: 5, accuracy: Low
        $x_1_2 = "MailClient.dll" ascii //weight: 1
        $x_1_3 = "MoveLeft" ascii //weight: 1
        $x_1_4 = "Release" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AAB_2147766743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AAB"
        threat_id = "2147766743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 6c 6c 00 43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 [0-6] 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 64 6c 6c 00 43 6f 6e 74 72 6f 6c 00 46 72 ?? 65 42 75 66 66 65 72 00 4e 65 74 53 65 72 76 65 72 53 74 61 72 74 00 4e 65 74 53 65 72 76 65 72 53 74 6f 70 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 64 6c 6c 00 42 61 63 6b 77 61 72 ?? 00 43 6f 6e 74 72 6f 6c 00 46 6f 72 77 61 72 64 00 46 72 65 65 42 75 66 66 65 72 00 50 61 75 73 65 00 52 65 6c 65 61 73 65 00 52 65 76 65 72 73 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 78 30 33 00 04 00 02 00 00 00 43 6f 6e 74 72 6f 6c 00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 46 ?? 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 64 6c 6c 00 3f 53 74 6f 70 40 40 [0-16] 00 43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 64 6c 6c 00 43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 [0-4] 4f 6e 4c 6f 61 64 00 [0-4] 4f 6e 55 6e 6c 6f 61 64 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: Low
        $x_1_7 = {2e 64 6c 6c 00 43 6f 6e 74 72 6f 6c 00 3f 44 4c 4c 43 6f 6e 74 72 6f 6c 40 40 40 40 [0-48] 00 3f 44 4c 4c 46 72 65 65 42 75 66 66 65 72 40 40 [0-48] 00 3f 44 4c 4c 52 65 6c 65 61 73 65 40 40 [0-48] 00 3f 44 4c 4c 53 74 61 72 74 40 40 [0-64] 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {3f 46 69 6e 64 40 40 59 [0-16] 00 3f 49 6e 69 74 40 40 59 [0-16] 00 3f 53 68 75 74 64 6f 77 6e 40 40 59 [0-16] 00 43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: Low
        $x_1_9 = {2e 64 6c 6c 00 5f 43 6f 6e 74 72 6f 6c 40 [0-8] 00 5f 46 72 65 65 42 75 66 66 65 72 40 [0-8] 00 5f 52 65 6c 65 61 73 65 40 [0-8] 00 5f 53 74 61 72 74 40}  //weight: 1, accuracy: Low
        $x_1_10 = {2e 64 6c 6c 00 43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 3f 52 65 6c 65 61 73 65 41 40 40 59 [0-16] 00 53 74 61 72 74 00}  //weight: 1, accuracy: Low
        $x_1_11 = {2e 64 6c 6c 00 3f 52 65 6c 65 61 73 65 41 40 40 59 [0-16] 00 43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: Low
        $x_1_12 = {2e 64 6c 6c 00 41 62 6f 75 74 44 69 61 6c 6f 67 50 ?? 6f 63 00 43 6f 6e 74 72 6f 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c ?? 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 46 72 65 65 42 75 66 66 65 72 00 4a 4e 49 5f 4f 6e 4c 6f 61 64 00 4a 4e 49 5f 4f 6e 55 6e 6c 6f 61 64 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Trickbot_ZC_2147766745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ZC"
        threat_id = "2147766745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {63 6f 72 65 2d 70 61 72 73 65 72 2e 64 6c 6c 00 42 61 6e 52 75 6c 65 00 43 6c 65 61 72 52 75 6c 65 73 00 43 6f 6e 66 69 67 49 6e 69 74 44 70 6f 73 74 00 43 6f 6e 66 69 67 49 6e 69 74 44 79 6e 61 6d 69 63 00 43 6f 6e 66 69 67 49 6e 69 74 53 74 61 74 69 63 00 45 6e 75 6d 44 70 6f 73 74 53 65 72 76 65 72}  //weight: 2, accuracy: High
        $x_2_2 = {2f 72 63 72 64 2f 00 00 2f 67 65 74 71 2f 00 00 2f 73 6e 61 70 73 68 6f 6f 74 2f}  //weight: 2, accuracy: High
        $x_2_3 = {b8 ab aa aa 2a 8b [0-5] 2b cf f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 3b f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_ZD_2147766748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ZD"
        threat_id = "2147766748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "F:\\Projects\\WebInject\\bin\\x86\\Release_logged\\payload32.pdb" ascii //weight: 2
        $x_2_2 = "Payload (build %s %s) injected" ascii //weight: 2
        $x_2_3 = {c6 44 24 4c 44 53 c6 44 24 51 59 33 db c6 44 24 52 44 8b d3 8a 44 24 40 88 5c 24 53}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AT_2147766777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AT"
        threat_id = "2147766777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 41 41 41 41 1c 00 81 ?? 41 41 41 41 75 ?? 81 ?? 04 41 41 41 41 75 ?? 81 ?? 08 41 41 41 41 75}  //weight: 1, accuracy: Low
        $x_1_2 = {55 41 56 56 57 53 48 83 ec [0-128] 8b ?? 48 ?? 8b ?? 40 ?? 8b ?? 38 ?? 8b ?? 30 ?? 8b ?? 28 ?? 8b ?? 20 ?? 8b ?? 10 ?? 8b ?? 18}  //weight: 1, accuracy: Low
        $x_1_3 = {48 83 e4 f0 48 8b 75 50 48 85 f6 74 40 48 8b 45 48 8b 4d 40 48 89 56 70 4c 89 46 78 4c 89 8e 80 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 8b 45 48 8b 4d 40 48 89 56 70 4c 89 46 78 4c 89 8e 80 00 00 00 8b c9 48 89 8e 88 00 00 00 48 89 86 90 00 00 00 48 89 b6 98 00 00 00 48 8b 4e 10 ff 56 30 48 8b 4e 10 ba ff ff ff ff ff 56 20}  //weight: 1, accuracy: High
        $x_1_5 = {8b 74 24 10 8b 44 16 24 8d 04 58 0f b7 0c 10 8b 44 16 1c 8d 04 88 8b 04 10 03 c2 eb db 4d 5a 80}  //weight: 1, accuracy: High
        $x_2_6 = {6a 00 e2 fc 48 8b ?? ?? 48 8b ?? 48 05 ?? ?? ?? ?? 48 89 ?? ?? ?? 48 89 ?? ?? 48 89 ?? ?? 48 c7 ?? ?? ff 00 00}  //weight: 2, accuracy: Low
        $x_2_7 = "HJIA/CB+FGKLNOP3RSlUVWXYZfbcdeaghi5kmn0pqrstuvwx89o12467" ascii //weight: 2
        $x_1_8 = "/5/spk/" ascii //weight: 1
        $x_1_9 = "pwgrab" ascii //weight: 1
        $x_1_10 = {00 6d 63 63 6f 6e 66 00}  //weight: 1, accuracy: High
        $x_1_11 = "/%s/%s/5/%s/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_BM_2147767736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BM!MSR"
        threat_id = "2147767736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0_4z$PLJD3@!ii0*xu!vqi_2_UK^eRE(X&Yx>xjadKHW$yKegjt<$1Qui#Vm5cyx" ascii //weight: 1
        $x_1_2 = "\\WindowsSDK7-Samples-master\\WindowsSDK7-Samples-master\\com\\administration\\spy\\Win32\\Release\\ComSpy.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_STB_2147767962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.STB"
        threat_id = "2147767962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 36 34 00 00 4c 64 72 41 63 63 65 73 73 52 65 73 6f 75 72 63 65 00 00 00 4c 64 72 46 69 6e 64 52 65 73 6f 75 72 63 65 5f 55 00 00 00 6e 74 64 6c 6c 2e 64 6c 6c 00 00 00 43 3a 5c 57 69 6e 64 6f 77 73 5c 6e 6f 74 65 70 61 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 68 6f 77 54 69 6d 65 36 34 2e 65 78 65 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_STB_2147767965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.STB!!Trickbot.STB"
        threat_id = "2147767965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "Trickbot: an internal category used to refer to some threats"
        info = "STB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 36 34 00 00 4c 64 72 41 63 63 65 73 73 52 65 73 6f 75 72 63 65 00 00 00 4c 64 72 46 69 6e 64 52 65 73 6f 75 72 63 65 5f 55 00 00 00 6e 74 64 6c 6c 2e 64 6c 6c 00 00 00 43 3a 5c 57 69 6e 64 6f 77 73 5c 6e 6f 74 65 70 61 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 68 6f 77 54 69 6d 65 36 34 2e 65 78 65 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_3 = {fd ff ff 8b 54 24 18 8d 4c 24 14 51 52 53 e8 ?? fe ff ff 83 [0-16] ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AA_2147770390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AA!MTB"
        threat_id = "2147770390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 3c 38 03 fe 50 8b c1 30 38 41 58}  //weight: 1, accuracy: High
        $x_1_2 = "This is a PE executable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AA_2147770390_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AA!MTB"
        threat_id = "2147770390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 56 01 00 00 f7 f9 bf 56 01 00 00 0f b6 ea 0f b6 04 2e 8d 0c 2e 03 c3 88 54 24 12 99 f7 ff 0f b6 da 03 f3 8b c6 88 54 24 13 e8 ?? ?? ?? ?? 0f b6 01 0f b6 16 03 c2 99 8b cf f7 f9 88 54 24 11}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0c 32 8b 7c 24 1c 30 0c 38 40 3b 44 24 20 89 44 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RM_2147776224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RM!MTB"
        threat_id = "2147776224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fb 8b 75 ?? 8b c1 8a 1c 31 80 c2 4f 32 da 47 88 1c 31 b9 05 00 00 00 99 f7 f9 89 7d ?? 85 d2 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RM_2147776224_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RM!MTB"
        threat_id = "2147776224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 e8 8d 44 6d ?? 2b d0 a1 ?? ?? ?? ?? 8b d8 0f af d8 8b c1 03 c2 8a 14 03 8b 44 24 ?? 8a 18 32 da 8b 54 24 ?? 88 18 8b 44 24 ?? 40 3b c2 89 44 24 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RM_2147776224_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RM!MTB"
        threat_id = "2147776224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 8a 1c 02 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d8 03 ?? ?? ?? ?? ?? 8b ?? ?? 8a 04 0a 32 c3 8b ?? ?? 8b 11 8b ?? ?? 88 04 11 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "DHKW%a)TEPwx%Kxav!QxrYAwtSBQjnNS@?hJFINLPbbvm7CN!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RM_2147776224_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RM!MTB"
        threat_id = "2147776224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 30 50 ff 75 ?? 53 6a 01 53 ff 75 ?? ff 55 ?? 85 c0 0f 95 c0 eb ?? 32 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {59 33 c0 bf e0 73 48 00 39 75 ?? f3 ab aa 89 1d ?? ?? ?? ?? 0f 86 ?? ?? ?? ?? 80 7d ?? 00 0f 84 ?? ?? ?? ?? 8d 4d ?? 8a 11 84 d2 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = "6IhN9GDr#aK+asK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RM_2147776224_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RM!MTB"
        threat_id = "2147776224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 e8 c7 45 ?? 42 00 00 00 e8 ?? ?? ?? ?? 8b 4d ?? 85 c9 76 ?? 8b 45 ?? 8d a4 24 ?? ?? ?? ?? 8a 10 80 f2 63 80 c2 63 88 10 83 c0 01 83 e9 01 75}  //weight: 10, accuracy: Low
        $x_5_2 = "BZYTY.png" ascii //weight: 5
        $x_1_3 = "OLEACC.dll" ascii //weight: 1
        $x_1_4 = "GetSystemInfo" ascii //weight: 1
        $x_1_5 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RM_2147776224_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RM!MTB"
        threat_id = "2147776224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 35 ?? ?? ?? ?? a0 ?? ?? ?? ?? 8a 14 0a 02 d0 8b 44 24 ?? 8a 1c 28 32 da 88 1c 28 8b 44 24 ?? 45 3b e8 72}  //weight: 1, accuracy: Low
        $x_1_2 = "x4NLsgxS#*JwG9__hTI!koRqc67eLd7d)hHOrXlHL8TX+yq>2Oyw95iFMCyI>Uy+LprZ(!li)Is+KRPwIZzz_3Dun?f4ZUq_?V" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RM_2147776224_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RM!MTB"
        threat_id = "2147776224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D$ ShelQP" ascii //weight: 1
        $x_1_2 = "D$,lExe" ascii //weight: 1
        $x_1_3 = "D$0cute" ascii //weight: 1
        $x_1_4 = "GetProcessVersion" ascii //weight: 1
        $x_1_5 = "GetCPInfo" ascii //weight: 1
        $x_1_6 = "GetSystemMetrics" ascii //weight: 1
        $x_1_7 = "AfxOldWndProc423" ascii //weight: 1
        $x_1_8 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_9 = "GetKeyState" ascii //weight: 1
        $x_1_10 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RTA_2147777011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RTA!MTB"
        threat_id = "2147777011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 bf ab 05 00 00 f7 ff 80 c2 3d 85 f6 76 ?? 8a 01 32 c2 02 c2 88 01 83 c1 01 83 ee 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RTA_2147777011_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RTA!MTB"
        threat_id = "2147777011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 4c 68 b8 51 47 00 ff 75 ?? ff 55 ?? 85 c0 74 ?? 8b 45 ?? ff 30 50 ff 75 ?? 53 6a 01 53 ff 75 ?? ff 55 ?? 85 c0 0f 95 c0 eb ?? 32 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "j<C*1rX&E59IqC2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RTA_2147777011_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RTA!MTB"
        threat_id = "2147777011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 8d 45 ?? 89 5d ?? 50 53 ff 75 ?? 6a 4c 68 ?? ?? ?? ?? ff 75 ?? e8 ?? ?? ?? ?? 85 c0 5f 74 ?? 8b 45 ?? ff 30 50 ff 75 ?? 53 6a 01 53 ff 75 ?? e8 ?? ?? ?? ?? 85 c0 0f 95 c0 eb ?? 32 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "y3fp#<IN6ZpA^)T" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RF_2147777854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RF!MTB"
        threat_id = "2147777854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b df 2b da 3b d9 72 ?? ff 15 ?? ?? ?? ?? eb ?? ff 15 ?? ?? ?? ?? 8b d8 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 8b 0e 8b 51 0c 88 04 1a b8 01 00 00 00 03 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RF_2147777854_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RF!MTB"
        threat_id = "2147777854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 35 ?? ?? ?? ?? 8d 45 ?? 0f af 05 ?? ?? ?? ?? 03 ea 03 c5 8b 6c 24 ?? 8a 14 08 8b 44 24 ?? 8a 1c 28 32 da 8b 54 24 ?? 88 1c 28 40 3b c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RTH_2147777879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RTH!MTB"
        threat_id = "2147777879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d0 8b 4d ?? 2b 4d ?? 0f b6 c1 83 ?? 20 33 d0 8b 4d ?? 88 11 8b 55 ?? 03 55 ?? 89 55 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RTH_2147777879_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RTH!MTB"
        threat_id = "2147777879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d1 03 f1 89 54 24 ?? 8a 00 89 74 24 ?? 88 44 24 ?? 8b 44 24 ?? 33 ff 33 ed 66 8b 3e 8b 74 24 ?? 8d 3c be 8b 32 8a 54 24 ?? 03 f9 03 f1 84 d2 74 ?? 8b 54 24 ?? 8b de 2b da 8a 14 03 84 d2 74}  //weight: 1, accuracy: Low
        $x_1_2 = "8E15Ast2R)t1ZBM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RTH_2147777879_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RTH!MTB"
        threat_id = "2147777879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 03 c7 f7 f1 8b 45 ?? 8a 0c 10 88 0e 88 1c 10 8b 0d ?? ?? ?? ?? 03 c2 ff 45 ?? 46 39 4d ?? 89 55 ?? 72}  //weight: 5, accuracy: Low
        $x_1_2 = "eJZ^nRM&YxmjU<bi^?s&tpk7wcW!R3_YMnQzB&^1CCWSO<q?c1RbMZaeUu%F5Em*rU&UT_r" ascii //weight: 1
        $x_1_3 = "FWSe8&OO1oB3oCXF@+6Uiw&1HzKR)(3n7fqPQcFqUZ7erO6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_RTH_2147777879_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RTH!MTB"
        threat_id = "2147777879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "t7O$aH!!G#*^Ipi" ascii //weight: 10
        $x_10_2 = "T1C_$leq1Bl!FeC" ascii //weight: 10
        $x_10_3 = "R54W@TWjW!r#mj3" ascii //weight: 10
        $x_10_4 = "Z5UwK^%(Ad!fc*7" ascii //weight: 10
        $x_10_5 = "HFv13&u6P7D0pye" ascii //weight: 10
        $x_10_6 = "auJvuU$Z2F7o2kf" ascii //weight: 10
        $x_10_7 = "1LR?V7MX2Ny9n!#" ascii //weight: 10
        $x_10_8 = "?g)z&4?zaUSvQo)" ascii //weight: 10
        $x_10_9 = "?hD$qbjyOLH3e%C" ascii //weight: 10
        $x_10_10 = "zLFq48R@1Z0b2Wg" ascii //weight: 10
        $x_10_11 = "f4PER(IDg#mht1W" ascii //weight: 10
        $x_10_12 = "e7wmsMU7yndj1f(" ascii //weight: 10
        $x_10_13 = "C!y432yq7G1C9pw" ascii //weight: 10
        $x_10_14 = "%Bl@<TZgk!ZWk)B" ascii //weight: 10
        $x_10_15 = "Fzr((<0w+Rt%$1f" ascii //weight: 10
        $x_10_16 = "2SD%^!ewPQS3CWw" ascii //weight: 10
        $x_1_17 = "Stup windows defender hahah" ascii //weight: 1
        $x_1_18 = "CryptAcquireContextW" ascii //weight: 1
        $x_1_19 = "CryptImportKey" ascii //weight: 1
        $x_1_20 = "CryptEncrypt" ascii //weight: 1
        $x_1_21 = "GetMonitorInfoA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_RFA_2147777938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RFA!MTB"
        threat_id = "2147777938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 66 8b 0b 8d 3c 8a 8b 4c 24 ?? 8a 15 ?? ?? ?? ?? 03 f8 8b 31 33 c9 03 f0 84 d2 74 ?? 8b ee 81 ed ?? ?? ?? ?? 8a 94 29 ?? ?? ?? ?? 84 d2 74}  //weight: 1, accuracy: Low
        $x_1_2 = "ZM?JgElb*Rha!+Z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RTC_2147778671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RTC!MTB"
        threat_id = "2147778671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3b eb 7e ?? 8b 54 24 ?? 8d 4c 2a ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c5 7c ?? 8d 45 ?? 83 f8 3e 88 9d ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
        $x_1_2 = "forti antivirus stupid protection" ascii //weight: 1
        $x_5_3 = "&T774a)w%*KPj9S" ascii //weight: 5
        $x_5_4 = "msuyDCYjF&IQ4EY" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_RW_2147778722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RW!MTB"
        threat_id = "2147778722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 8b 4d ?? 8b 09 8a 0c 39 02 0d ?? ?? ?? ?? 30 08 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? ff 45 ?? 8b c6 2b c1 6b c0 70 03 45 ?? 39 45 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RW_2147778722_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RW!MTB"
        threat_id = "2147778722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "^2?SnrwkZSzpuPI" ascii //weight: 10
        $x_10_2 = "Fuck Def" ascii //weight: 10
        $x_1_3 = "GetKeyState" ascii //weight: 1
        $x_1_4 = "CallNextHookEx" ascii //weight: 1
        $x_1_5 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_6 = "GetMonitorInfoA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_RW_2147778722_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RW!MTB"
        threat_id = "2147778722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 03 c6 f7 f7 8b f2 8a 04 2e 88 01 8b 44 24 ?? 88 1c 2e 8b 3d ?? ?? ?? ?? 40 41 3b c7 89 44 24 18 72}  //weight: 1, accuracy: Low
        $x_1_2 = "#a)F&SPfcEgrGtFc4trjy5Js57!wMAlsL?0dlJAG5>bSGrbK7@u3saXllteQ1^*qjW*5Hz&DVPPi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RW_2147778722_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RW!MTB"
        threat_id = "2147778722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 04 80 2b d0 03 d5 8b 2d ?? ?? ?? ?? 03 d5 8b 6c 24 ?? 8a 14 0a 8a 45 ?? 32 c2 43 88 45 ?? 8b 44 24 ?? 3b d8 0f}  //weight: 1, accuracy: Low
        $x_1_2 = "1P+3FN?fe(EAiBbIV%qTj%Aj_LcB&s2pK9yYh#rIH<mIM&bX*m!^(p&ul^Q#*9>xBgam)3dYyHo^Du$F>z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RW_2147778722_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RW!MTB"
        threat_id = "2147778722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e9 02 8d b8 ?? ?? ?? ?? b8 01 01 01 01 f3 ab 8b ca 83 e1 03 f3 aa 8b 4c 24 ?? 8b 54 24 ?? 8d 44 24 ?? 50 53 51 6a ?? 68 ?? ?? ?? ?? 52 89 5c 24 ?? ff 54 24 ?? 85 c0 75 ?? 5f 5e 5d 32 c0}  //weight: 5, accuracy: Low
        $x_1_2 = "_z1LBudXVcz<gTb" ascii //weight: 1
        $x_1_3 = "s5VM?9D@Rq!!sUZ" ascii //weight: 1
        $x_1_4 = "msuyDCYjF&IQ4EY" ascii //weight: 1
        $x_1_5 = "Brxu_laD&Qhe9So" ascii //weight: 1
        $x_1_6 = "rDl<OlvNrxw0n52" ascii //weight: 1
        $x_1_7 = "4l2a%8XzeOb8VG(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trickbot_VIS_2147780971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.VIS!MTB"
        threat_id = "2147780971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c 8b 4d f8 8a 14 33 03 c1 83 c4 0c 30 10 41 3b 4d 10 89 4d f8 72 9f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_VIS_2147780971_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.VIS!MTB"
        threat_id = "2147780971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 2e 88 04 33 88 0c 2e 0f b6 04 33 0f b6 c9 03 c1 33 d2 f7 35 ?? ?? ?? ?? 33 c9 33 c0 8b 44 24 10 8a 0c 38 8a 14 32 32 ca 88 0c 38 8b 4c 24 20 40 3b c1 89 44 24 10 72 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_M_2147783204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.M!MTB"
        threat_id = "2147783204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 17 68 05 e8 00 00 52 e8}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 10 00 00 ?? 6a 00 ff d3}  //weight: 1, accuracy: Low
        $x_1_3 = {8a d9 2a da 32 19 32 d8 88 19 03 cf 3b 4d}  //weight: 1, accuracy: High
        $x_1_4 = "Hey, I miss?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_Z_2147783779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.Z!MTB"
        threat_id = "2147783779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5d 08 8b cb c1 e9 10 83 e1 3f 8b c1 8b d1 d1 e8 33 f6 0f b6 c0 46 23 c6 23 d6 c1 e0 04 c1 e2 05 0b d0 8b c1 c1 e8 02 0f b6 c0 23 c6 c1 e0 03 0b d0 8b c1 c1 e8 03 0f b6 c0 23 c6 c1 e0 02 0b d0 8b c1 c1 e8 04 0f b6 c0 23 c6 c1 e9 05 0b d0 0f b6 c1 23 c6 8d 7d e0 03 c0 6a 07 0b d0 33 c0 59 f3 ab d9 75 e0 8b 4d e4 8b c1 33 c2 83 e0 3f 33 c8 89 4d e4 d9 65 e0}  //weight: 1, accuracy: High
        $x_1_2 = {c1 eb 18 83 e3 3f 8b c3 8b cb d1 e8 23 ce 0f b6 c0 23 c6 c1 e1 05 c1 e0 04 0b c8 8b c3 c1 e8 02 0f b6 c0 23 c6 c1 e0 03 0b c8 8b c3 c1 e8 03 0f b6 c0 23 c6 c1 e0 02 0b c8 8b c3 c1 e8 04 0f b6 c0 23 c6 0b c8 c1 eb 05 0f b6 c3 23 c6 03 c0 5f 0b c8 39 35 60 71 2b 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EC_2147784097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EC!MTB"
        threat_id = "2147784097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 19 0f be 14 08 8b c3 03 f2 25 ff 00 00 00 33 d2 03 c6 f7 f7 8b f2 8a 04 2e 88 01 8b 44 ?? 18 88 1c 2e 8b 3d 28 81 01 10 40 41 3b c7}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 46 01 33 d2 f7 35 ?? ?? ?? ?? 8b f2 33 d2 8a 1c 0e 8b c3 88 5c 24 ?? 25 ff 00 00 00 03 c7 f7 35 ?? ?? ?? ?? 8b fa 8b 54 24 14 81 e2 ff 00 00 00 8a 04 0f 88 04 0e 33 c0 88 1c 0f 8a 04 0e 03 c2 33 d2 f7 35 28 81 01 10 a1 ?? ?? ?? ?? 2b d0 8b 44 24 ?? 8a 14 0a 8a 1c 28 32 da 88 1c 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EE_2147787340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EE!MTB"
        threat_id = "2147787340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 2b d3 89 45 ?? 89 55 ?? 89 7d ?? 8a 0c 02 80 f1 80 3b c6 73 ?? 8b ff 8a d0 2a d3 80 e2 80 32 10 32 d1 88 10 03 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {6a e0 33 d2 58 f7 f1 3b 45 ?? ?? ?? ?? ?? ?? ?? ?? c7 00 0c 00 00 00 33 c0 5d c3 0f af 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EF_2147787341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EF!MTB"
        threat_id = "2147787341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 33 d2 f7 75 ?? 8b 45 ?? 8d 0c 1f 88 1c 0e 43 8a 04 02 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 1e 8b 7d ?? 0f be 14 30 0f b6 c3 03 fa 33 d2 03 c7 f7 f1 8b 45 ?? 8a 0c 10 88 0e 88 1c 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EF_2147787341_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EF!MTB"
        threat_id = "2147787341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c0 2f 83 c0 47 99 6a 7f 59 f7 f9 88 55 ?? 33 c0 40 6b c0 03 0f b6 80 ?? ?? ?? ?? 6b c0 2f 83 c0 47 99 6a 7f 59 f7 f9 88 55 ?? 33 c0 40 c1 e0 02 0f b6 80 ?? ?? ?? ?? 6b c0 2f 83 c0 47 99 6a 7f 59 f7 f9 88 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EH_2147787342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EH!MTB"
        threat_id = "2147787342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af d5 0f af d8 0f af d5 2b da 33 d2 8a 14 0f 83 eb 02 0f af d8 33 c0 8a 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 ?? 03 da 2b dd 8b 2d ?? ?? ?? ?? 03 dd 8a 14 0b 8a 18 32 da 8b 54 24 ?? 88 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EH_2147787342_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EH!MTB"
        threat_id = "2147787342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 06 2b c1 89 45 ?? 8b 55 ?? 8b 45 ?? 03 42 ?? 8b 0d ?? ?? ?? ?? 69 c9 f8 00 00 00 2b c1 8b 15 ?? ?? ?? ?? 69 d2 f8 00 00 00 2b c2 8b 0d ?? ?? ?? ?? 69 c9 f8 00 00 00 03 c1 89 45 ?? 8b 55 ?? 8b 42 ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b c1 89 45 f0 8b 55 ?? 03 55 ?? ?? ?? ?? ?? ?? 6b c0 28 03 d0 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 6b c9 28 2b d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AO_2147788125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AO!MTB"
        threat_id = "2147788125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 61 6e 74 c7 45 ?? 52 65 6c 65 ff 15 ?? ?? ?? ?? 68 f8 2a 00 00 ff ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c1 51 8b cf 81 c1 ?? ?? 00 00 c1 e0 02 03 c8 8b 01 59 03 d0 52}  //weight: 1, accuracy: Low
        $x_1_3 = {0c 8b c5 b9 ?? 00 00 00 c1 e1 02 2b c1 8b 00 89 45 ?? 6a ?? 59 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AP_2147788126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AP!MTB"
        threat_id = "2147788126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tabdll_x86.dll" ascii //weight: 1
        $x_1_2 = ".locker" ascii //weight: 1
        $x_1_3 = ".xtab" ascii //weight: 1
        $x_1_4 = "0123456789_qwertyuiopasdfghjklzxcvbnm" ascii //weight: 1
        $x_1_5 = "ReflectiveLoader" ascii //weight: 1
        $x_1_6 = "CreateObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_CI_2147788494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.CI!MTB"
        threat_id = "2147788494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 3c 29 33 d2 88 0c 38 8b c1 f7 74 24 ?? 8b 44 24 ?? 41 8a 14 02 88 17}  //weight: 1, accuracy: Low
        $x_1_2 = {b3 05 8b f2 8a 15 ?? ?? ?? ?? 8a c2 f6 e9 8b 0d ?? ?? ?? ?? 02 c1 f6 eb 8a d8 8a c2 8a d3 8b 1d ?? ?? ?? ?? fe c0 f6 eb 2a d0 2b fb 80 c2 02 8d 2c 89 8a c2 8a 54 24 ?? f6 e9 02 c2 8b 15 ?? ?? ?? ?? 0f af fa 03 fd 2b fb 83 c7 02 0f af f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_CK_2147788942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.CK!MTB"
        threat_id = "2147788942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 f6 3b d3 74 ?? 0f b6 0c 17 0f b6 04 1f 88 0c 1f [0-16] 88 04 17}  //weight: 1, accuracy: Low
        $x_1_2 = {33 db 8a e0 c0 e8 02 2a 5c 24 ?? c0 e4 06 2a dc 8a 64 24 ?? f6 db 88 5c 24 ?? 8a f8 80 f7 30 22 f8 88 64 24 ?? c0 e4 04 8a c7 8a dc 80 e7 3c 80 cc 03 f6 d0 f6 d3 0a d8 24 03 0a f8 f6 d3 8a 44 24 ?? 32 e7 0a dc 88 5c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_CL_2147788967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.CL!MTB"
        threat_id = "2147788967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 03 55 fc 0f b6 02 03 45 f0 8b 4d f4 03 4d fc 0f be 11 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 55 f0 8b 45 08 03 45 fc 8a 08 88 4d fb 8b 55 08 03 55 fc 8b 45 08 03 45 f0 8a 08 88 0a 8b 55 08 03 55 f0 8a 45 fb 88 02 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 03 45 fc 8a 4d fc 88 08 8b 45 fc 33 d2 f7 75 10 8b 45 f4 03 45 fc 8b 4d 0c 8a 14 11 88 10 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_CM_2147789026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.CM!MTB"
        threat_id = "2147789026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "2\\dll\\Release\\Test01.pdb" ascii //weight: 1
        $x_1_2 = "1.dll" ascii //weight: 1
        $x_1_3 = "Dpi800" ascii //weight: 1
        $x_1_4 = "GetMouse" ascii //weight: 1
        $x_1_5 = "[ GOOD ]" ascii //weight: 1
        $x_1_6 = {6a 40 68 00 10 00 00 [0-6] 6a 00 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_CM_2147789026_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.CM!MTB"
        threat_id = "2147789026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 3c 0b 33 d2 88 0c 38 8b c1 f7 74 24 ?? 8b 44 24 ?? 41 8a 14 02 88 17 8b 3d ?? ?? ?? ?? 3b cf 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 19 0f be 14 08 8b c3 03 f2 25 ff 00 00 00 33 d2 03 c6 f7 f7 8b f2 8a 04 2e 88 01 8b 15 [0-18] 03 c2 8b 15 ?? ?? ?? ?? 03 c2 8d 14 ?? 8b c6 2b c2 88 1c 28 8b 44 24 ?? 8b 3d ?? ?? ?? ?? 40 41 3b c7 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AZ_2147789179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AZ!MTB"
        threat_id = "2147789179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c3 2a 44 24 ?? 83 c4 04 32 03 51 32 44 24 ?? 52 88 03}  //weight: 1, accuracy: Low
        $x_1_2 = "joeboxcontrol.exe" ascii //weight: 1
        $x_1_3 = "x32dbg.exe" ascii //weight: 1
        $x_1_4 = "Checking process of malware analysis tool" ascii //weight: 1
        $x_1_5 = "hello heaven" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_CJ_2147794362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.CJ!MTB"
        threat_id = "2147794362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hgfhgdhgdh3" ascii //weight: 1
        $x_1_2 = "winpe.exe" ascii //weight: 1
        $x_1_3 = "hgfhgdhgdh1" ascii //weight: 1
        $x_1_4 = ")jQX?0Km#kO0raG$@c$&APVD<ROOSr1hj$CCD@l2#fY<>e5?CNaD" ascii //weight: 1
        $x_1_5 = "003wntczMGclFHx!B#kMi+i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_CJ_2147794362_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.CJ!MTB"
        threat_id = "2147794362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 45 ?? 8a 4d ?? 88 08 8b 45 ?? 33 d2 f7 75 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? 8a 14 11 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d0 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 d0 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 d0 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 4d 08 8a 45 fc 88 04 11 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EK_2147794509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EK!MTB"
        threat_id = "2147794509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 03 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b ca a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c0 f8 00 00 00 03 d0 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 69 c9 f8 00 00 00 03 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 69 c0 f8 00 00 00 03 d0 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 69 c9 f8 00 00 00 03 d1 89 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_HD_2147795727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.HD!MTB"
        threat_id = "2147795727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 f8 03 c2 0f b6 14 33 89 45 08 8b 45 fc 0f b6 04 30 03 c2 33 d2 f7 35 ?? ?? ?? ?? 58 2b 05 ?? ?? ?? ?? 0f af c1 0f af c1 48 0f af c1 03 fa 03 c7 8a 0c 30 8b 45 08 30 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_EV_2147796149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.EV!MTB"
        threat_id = "2147796149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 02 2b d0 03 d3 88 0c 32 8b 2d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b cd 0f af cd 8b d1 0f af 0d ?? ?? ?? ?? 2b d0 0f af d5 8d 04 42 2b 05 ?? ?? ?? ?? 03 44 24 10 8b 54 24 20 03 c2 0f b6 14 37 89 44 24 14 0f b6 04 33 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 14 41 0f af cd 8b 2d ?? ?? ?? ?? 2b d1 03 d5 8a 0c 32 8a 10 32 d1 8b 4c 24 24 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_BF_2147796248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.BF!MTB"
        threat_id = "2147796248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 6c 24 1c 0f af c6 8d 2c 49 2b e8 a1 ?? ?? ?? ?? 0f af e9 0f af e9 03 d5 8d 0c 76 8d 04 82 2b c1 8a 0c 38 8b 44 24 1c 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d1 8b c1 0f af d1 0f af c1 0f af d1 8d 2c f6 89 44 24 24 2b d5 8b 2d ?? ?? ?? ?? 03 54 24 14 03 c5 d1 e0 8b 6c 24 10 2b c6 0f be 14 1a 8d 04 43 03 ea 33 d2 0f b6 04 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_FA_2147796831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.FA!MTB"
        threat_id = "2147796831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 41 01 b9 4b 40 00 00 f7 f1 bb 4b 40 00 00 8b ca 0f b6 04 31 33 d2 03 c7 bf 4b 40 00 00 f7 f7 8b fa 8b 55 f8 8a 14 0a 8a 04 37 88 04 31 88 14 37 0f b6 04 31 0f b6 d2 03 c2 33 d2 f7 f3 8b 45 fc 40 89 45 fc 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 03 55 f4 8a 1c 32 8b 55 f0 30 5c 02 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_FB_2147796832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.FB!MTB"
        threat_id = "2147796832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c2 81 c2 13 c6 85 71 83 ea 01 81 ea 13 c6 85 71 0f af c2 83 e0 01 83 f8 00 0f 94 c3 83 f9 0a 0f 9c c7 88 d8 20 f8 30 fb 08 d8 a8 01}  //weight: 1, accuracy: High
        $x_1_2 = {81 ea 21 87 22 ee 83 ea 01 81 c2 21 87 22 ee 0f af c2 83 e0 01 83 f8 00 0f 94 c3 83 f9 0a 0f 9c c7 88 d8 34 ff 88 fc 80 f4 ff b1 01 80 f1 01 88 c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_FD_2147796925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.FD!MTB"
        threat_id = "2147796925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b db 11 89 86 c0 05 00 00 29 d8 8b 9e c0 05 00 00 81 eb 61 47 ea e3 01 d8 8b 9e c0 05 00 00 29 c3 81 eb 06 0a 6d 5a 83 eb d5 81 c3 06 0a 6d 5a 8b 86 c0 05 00 00 2d 61 47 ea e3 01 c3 89 d8 89 96 bc 05 00 00 99 bb 7f 00 00 00 f7 fb 88 17 8b 96 20 06 00 00 8a 52 01 88 96 8b 06 00 00 89 be 84 06 00 00 0f b6 96 8b 06 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_FC_2147797017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.FC!MTB"
        threat_id = "2147797017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AloperNoteW" ascii //weight: 1
        $x_1_2 = {89 7d e4 81 ef 4e c9 ea 32 83 ef 01 81 c7 4e c9 ea 32 89 45 e0 8b 45 e4 0f af c7 83 e0 01 83 f8 00 0f 94 c0 24 01 88 45 ee 83 fb 0a 0f 9c c0 24 01 88 45 ef c7 45 e8 7f a3 d9 4d}  //weight: 1, accuracy: High
        $x_1_3 = {89 c2 81 c2 e2 47 3e 9e 83 ea 01 81 ea e2 47 3e 9e 0f af c2 83 e0 01 83 f8 00 0f 94 c0 83 f9 0a 0f 9c c4 88 c1 20 e1 30 e0 08 c1 f6 c1 01 ba 3c 3b fb 29 be 0b 74 9a 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GD_2147799296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GD!MTB"
        threat_id = "2147799296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 08 0f b6 55 ?? 33 ca 8b 45 ?? 2b 45 ?? 0f b6 d0 81 e2 e0 00 00 00 33 ca 8b 45 ?? 88 08 8b 4d ?? 03 4d ?? 89 4d ?? eb 3c 00 8b 55 ?? 3b 55 ?? 73}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AB_2147799488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AB!MTB"
        threat_id = "2147799488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b c8 88 4d [0-8] e8 ?? ?? ?? ?? 83 c4 ?? 0f b6 55 ?? 0f b6 45 ?? 33 c2 88 45 [0-8] e8 ?? ?? ?? ?? 83 c4 ?? 8a 4d ?? 80 c1 ?? 88 4d ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 ?? 8b 55 ?? 8a 45 ?? 88 02 70 00 0f b6 45 ?? 0f b6 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GGL_2147806115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GGL!MTB"
        threat_id = "2147806115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 70 30 3f a0 ?? ?? ?? ?? 23 22 c4 00 30 0d ?? ?? ?? ?? e6 8c 02 e4 6d 12 11 48 38 21 40 73 bc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_2147807557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.simd!MTB"
        threat_id = "2147807557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "simd: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 0f 4e 33 c1 4e 88 07 4e 85 d2 75 06 8b 55 14 8b 75 10 59 47 e2 e6}  //weight: 10, accuracy: High
        $x_1_2 = "bijaweed.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_GML_2147807959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.GML!MTB"
        threat_id = "2147807959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 fc 03 f0 83 c6 20 8b 3e 83 ee 0c 8b 06 03 7d fc 89 45 f4 83 ee 14 33 d2 8b 5d 0c c3}  //weight: 10, accuracy: High
        $x_5_2 = {8b d0 8b 5d f0 b8 00 00 00 00 42 8b 0a 40 81 e1 ff 00 00 00 75 f4}  //weight: 5, accuracy: High
        $x_5_3 = {83 c3 01 8b 03 41 38 d0 75 f6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_AT_2147819740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.AT!MTB"
        threat_id = "2147819740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 0a 33 d2 5b f7 f3 8b 45 08 8a 54 0a 04 30 54 08 0e 40 3b 07 89 45 08 72 e6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MA_2147834234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MA!MTB"
        threat_id = "2147834234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 14 03 83 c3 04 8b 46 2c 0f af 56 54 05 0e 19 07 00 09 46 18 8b 46 70 8b 8e 94 00 00 00 88 14 01 ff 46 70 8b 46 20}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_RPP_2147840362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.RPP!MTB"
        threat_id = "2147840362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 01 53 53 6a 00 ff d6 6a 00 53 53 6a 00 ff d6 33 d2 8b c7 6a 64 59 f7 f1 8a 44 14 18 30 04 2f 47 81 ff 00 d0 07 00 7c d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_ASER_2147900219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ASER!MTB"
        threat_id = "2147900219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 00 00 80 34 1e ?? 68 ?? ?? ?? 00 e8 ?? ?? ?? 00 80 04 1e ?? 68 ?? ?? ?? 00 e8 ?? ?? ?? 00 80 04 1e ?? 83 c4 40 68 ?? ?? ?? 00 e8 ?? ?? ?? 00 80 04 1e ?? 83 c4 04 46 3b f7 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_ASES_2147900220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ASES!MTB"
        threat_id = "2147900220"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 c1 e8 18 33 c1 69 c8 91 e9 d1 5b 69 45 0c 91 e9 d1 5b 33 c8 89 4d 0c 3b 55 f8 0f}  //weight: 1, accuracy: High
        $x_1_2 = "Z81xbyuAua" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_ASET_2147900235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.ASET!MTB"
        threat_id = "2147900235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e8 18 33 c1 69 c0 95 e9 d1 5b 33 d8 89 45 0c 83 6d f4 01 89 5d fc 0f}  //weight: 1, accuracy: High
        $x_1_2 = "Z81xbyuAua" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Trickbot_MKV_2147929220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbot.MKV!MTB"
        threat_id = "2147929220"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {30 c8 8b 4d f0 88 01 8b 45 ?? 0f b6 00 8b 4d ?? fe c0 88 01 8b 45 ?? 0f b6 00 8b 4d d4 88 01 8b 45 ?? 8b 45 d0 8b 45 d0 8b 45 d0 b8 49 d2 18 71 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

