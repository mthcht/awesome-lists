rule Trojan_Win32_Zbot_CL_2147636745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.CL"
        threat_id = "2147636745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 2e 6e 65 77 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 77 76 3d 25 73 26 75 69 64 3d 25 73 26 6d 69 64 3d 25 73 26 61 62 62 72 3d 25 73 26 76 65 72 69 6e 74 3d 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 48 69 64 65 44 65 73 6b 74 6f 70 49 63 6f 6e 73 5c 43 6c 61 73 73 69 63 53 74 61 72 74 4d 65 6e 75 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 6f 73 74 73 50 72 6f 64 75 63 74 4d 75 74 65 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_B_2147739873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.B!MTB"
        threat_id = "2147739873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 10 00 00 00 8a 0c 37 30 0e 46 48 75 f7}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Users\\degrigis\\documents\\visual studio 2010\\Projects\\DolphinDropperAES\\Release\\DolphinDropperAES.pdb" ascii //weight: 1
        $x_1_3 = {88 48 11 0f b6 50 f2 32 55 ff 8d 4e fe 88 50 12 83 c0 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_2147741592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot!MTB"
        threat_id = "2147741592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 57 53 8b 5d 94 85 df c1 c3 18 8b 0b 8b 45 80 85 c3 c1 c8 02 3b c8 0f 85 bb fb ff ff}  //weight: 1, accuracy: High
        $x_2_2 = {33 c8 33 ff ba 00 00 fc 03 c1 ca 1a e9 b7 01 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {8b 45 a4 85 c3 d1 c0 03 f0 8b 16 c1 c2 17 83 e2 09 03 ca 4b 89 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RL_2147743007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RL!MTB"
        threat_id = "2147743007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 03 33 c6 03 02 2b 02 89 01 03 15 ?? ?? ?? ?? 83 c7 01 8b c7 ff 75 18 8f 45 e8 2b 45 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RB_2147745100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RB!MTB"
        threat_id = "2147745100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 02 33 45 fc 8b 4d f8 89 01 c7 45 d0 16 00 00 00 8b e5 5d c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RB_2147745100_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RB!MTB"
        threat_id = "2147745100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d b2 6e 00 00 89 45 18 8b 4d f0 83 c1 08 2b 4d 14 89 4d ec c7 45 e4 c0 f1 0f 00 8b 55 ec 69 d2 7b 46 01 00 a1 ?? ?? ?? ?? 2b c2 89 45 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RB_2147745100_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RB!MTB"
        threat_id = "2147745100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YRJZEBUMJGCHNLQXOPKKQWDOKD" ascii //weight: 1
        $x_1_2 = "BGBAQFXQZ" ascii //weight: 1
        $x_1_3 = "SOWQKFT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RB_2147745100_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RB!MTB"
        threat_id = "2147745100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Clenchais de'cor te'le'guideront" wide //weight: 1
        $x_1_2 = "puceaux brancardiers" wide //weight: 1
        $x_1_3 = "jaillissaient adjurez darder" wide //weight: 1
        $x_1_4 = "desengourdir impartiaux" wide //weight: 1
        $x_1_5 = "nr4ADjU+dGtndWkAcGlq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DSK_2147745377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DSK!MTB"
        threat_id = "2147745377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\xYpWD3Ft.exe" wide //weight: 1
        $x_1_2 = "C:\\zrsu2jKZ.exe" wide //weight: 1
        $x_1_3 = "C:\\V4qooVnJ.exe" wide //weight: 1
        $x_1_4 = "C:\\ZLUTSaoF.exe" wide //weight: 1
        $x_1_5 = "C:\\rcvse5cw.exe" wide //weight: 1
        $x_1_6 = "C:\\EtyI3k7I.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Zbot_RC_2147747845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RC!MTB"
        threat_id = "2147747845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 0b 42 51 00 8b 0d ?? ?? ?? ?? bb ?? ?? ?? ?? 30 03 43 49 85 c9 75 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RC_2147747845_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RC!MTB"
        threat_id = "2147747845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 6b fa 03 00 01 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8a 0c 30 a1 ?? ?? ?? ?? 88 0c 30 46 8b 0d ?? ?? ?? ?? 3b f1 72}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 10 30 04 3b 43 3b de 7c e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RC_2147747845_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RC!MTB"
        threat_id = "2147747845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {98 6c 00 8b c6 05 ?? 98 6c 00 ec c6 05 ?? 98 6c 00 83 c6 05 ?? 98 6c 00 c4 c6 05 ?? 98 6c 00 f0 c6 05 ?? 98 6c 00 b8 c6 05 ?? 98 6c 00 00 c6 05 ?? 98 6c 00 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RB_2147749142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RB!MSR"
        threat_id = "2147749142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Antirepublicanism" ascii //weight: 1
        $x_1_2 = "Disestablismentarianism" ascii //weight: 1
        $x_1_3 = "Bronchos spise" ascii //weight: 1
        $x_1_4 = "insecuration" ascii //weight: 1
        $x_1_5 = "Gunsight7" ascii //weight: 1
        $x_1_6 = "idoneousness" ascii //weight: 1
        $x_1_7 = "frolickly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_PVD_2147750020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.PVD!MTB"
        threat_id = "2147750020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 32 8b 95 ?? ?? ff ff 83 c2 03 89 95 ?? ?? ff ff 8b 95 ?? ?? ff ff 83 ea 04 89 95 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {8b bd 14 fe ff ff 30 14 39 83 fb 30 7e}  //weight: 2, accuracy: High
        $x_2_3 = {03 c1 8a 4c 24 10 03 c6 8a 10 32 d1 88 10 06 00 8b 0d}  //weight: 2, accuracy: Low
        $x_2_4 = {8a 4c 2b 03 8a d1 88 4c 24 10 80 e2 f0 c0 e2 02 0a 14 2b 88 54 24 12 3d e9 05 00 00 0f 84}  //weight: 2, accuracy: High
        $x_2_5 = {8b ca b8 9a 02 00 00 03 c1 2d 9a 02 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 07 00 8b d7 b8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zbot_XLZ_2147750724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.XLZ!MTB"
        threat_id = "2147750724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c0 c0 01 85 ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 32 85 ?? ?? ?? ?? 3b 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 7f ?? 8b 8d ?? ?? ?? ?? 01 8d ?? ?? ?? ?? 88 06 39 1d ?? ?? ?? ?? 75 ?? 8b 85 ?? ?? ?? ?? 99 6a 35 59 f7 f9 69 c0 20 2a 01 00 2b c8 01 8d ?? ?? ?? ?? 81 3d ?? ?? ?? ?? e8 03 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_V_2147752791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.V!MTB"
        threat_id = "2147752791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0b 8b 55 f8 81 ea 82 f0 53 75 03 da 8b 03 c1 c0 0f 83 e0 13 03 c8 4f 89 0e ba cc c3 f5 dd 81 f2 c8 c3 f5 dd}  //weight: 1, accuracy: High
        $x_1_2 = {81 ea ec 39 dd 5f 03 da 8b 03 c1 c0 0f 83 e0 13 03 c8 4f 89 0e ba 00 00 00 10 c1 c2 06 03 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_PVE_2147754532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.PVE!MTB"
        threat_id = "2147754532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 b7 59 e7 1f f7 a5 28 ff ff ff 8b 85 28 ff ff ff 81 85 6c fd ff ff ?? ?? ?? ?? 81 6d ac ?? ?? ?? ?? 81 85 c4 fd ff ff ?? ?? ?? ?? 30 0c 37}  //weight: 2, accuracy: Low
        $x_2_2 = {0f be 11 0f b6 85 63 ff ff ff 33 d0 8b 4d 08 03 4d 0c 88 11 8b 55 0c 83 ea 01 89 55 0c e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zbot_DSA_2147757211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DSA!MTB"
        threat_id = "2147757211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 07 03 ce 88 02 4e 4b 03 f0 f7 d0 42 48 f7 d1 4e 47 f7 d9 0b db 75 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DEC_2147761206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DEC!MTB"
        threat_id = "2147761206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d 87 10 00 00 8b 4d 08 89 01}  //weight: 1, accuracy: High
        $x_1_2 = "08rtg0imuwrh9y3uj450yij3t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zbot_DED_2147762004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DED!MTB"
        threat_id = "2147762004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 2b c2 1b f1 a3 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 69 c9 ec e7 00 00 03 0d ?? ?? ?? ?? 89 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {6b d2 61 03 ca 0f b6 05 ?? ?? ?? ?? 2b c1 a2 ?? ?? ?? ?? 8b 4d dc 83 e9 01 89 4d dc 8b 15 ?? ?? ?? ?? 6b d2 61 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RI_2147773694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RI!MTB"
        threat_id = "2147773694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 44 fa e1 99 e2 c5 c5 75 bf e6 0f 3d 7e 9f 75 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RI_2147773694_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RI!MTB"
        threat_id = "2147773694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IE Cookies:" ascii //weight: 1
        $x_1_2 = "zkrvvcnmaebNUf\\VWXIT<AKG<B" ascii //weight: 1
        $x_1_3 = "zkrvvcnmaebNbcZ" ascii //weight: 1
        $x_1_4 = "fk{vtelpp]hg[_\\HaQTPQGMJ" ascii //weight: 1
        $x_1_5 = "fk{vtelpp]hg[_\\HXMZ[QRI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RI_2147773694_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RI!MTB"
        threat_id = "2147773694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "d:\\11\\Wheel\\Heard\\Shout\\Student\\Weight\\Except\\87\\40\\55\\69\\yellow\\40\\Think.pdb" ascii //weight: 10
        $x_1_2 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_3 = "GetCPInfo" ascii //weight: 1
        $x_1_4 = "GetLocaleInfoW" ascii //weight: 1
        $x_1_5 = "GetFileType" ascii //weight: 1
        $x_1_6 = "GetEnvironmentStringsW" ascii //weight: 1
        $x_1_7 = "CreateEventExW" ascii //weight: 1
        $x_1_8 = "GetTickCount64" ascii //weight: 1
        $x_1_9 = "_TrackMouseEvent" ascii //weight: 1
        $x_1_10 = "InitializeCriticalSectionEx" ascii //weight: 1
        $x_1_11 = "LC_COLLATE=C;LC_CTYPE=C;LC_MONETARY=C;LC_NUMERIC=C;LC_TIME=C" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RM_2147774347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RM!MTB"
        threat_id = "2147774347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetProcessWindowStation" ascii //weight: 1
        $x_10_2 = "c:\\FindHeard\\EndLook\\ChartBegan\\WinSentence\\Rain.pdb" ascii //weight: 10
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "GetTickCount" ascii //weight: 1
        $x_1_5 = "GetLocaleInfoA" ascii //weight: 1
        $x_1_6 = "http://www.enoughthose.de" wide //weight: 1
        $x_1_7 = "GetEnvironmentStrings" ascii //weight: 1
        $x_1_8 = "GetLogicalProcessorInformation" ascii //weight: 1
        $x_10_9 = "c:\\thenSpot\\ShortFell\\RightBranch\\Reachsound\\OneGrass\\An.pdb" ascii //weight: 10
        $x_1_10 = "GetLocaleInfoEx" ascii //weight: 1
        $x_1_11 = "GetCurrentDirectoryA" ascii //weight: 1
        $x_1_12 = "1#SNAN" ascii //weight: 1
        $x_1_13 = "1#QNAN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zbot_RP_2147774348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RP!MTB"
        threat_id = "2147774348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 ac 00 74 64 8d 0c 10 0f af ca 31 c1 01 d1 80 c1 f8 88 0d ?? ?? ?? ?? 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {30 1c 06 89 d8 c1 eb 18 89 df c1 e0 08 89 45 ?? f7 d0 f7 d7 89 45 ?? 68 4f 00 6b 9b 50 e8 ?? ?? ?? ?? 83 c4 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SA_2147777958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SA!MTB"
        threat_id = "2147777958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL3NydjcwLnB1dGRyaXZlLmNvbS9wdXRzdG9yYWdlL0Rvd25sb2FkRmlsZUhhc" ascii //weight: 1
        $x_1_2 = "SELECT origin_url, username_value, password_value FROM logins" ascii //weight: 1
        $x_1_3 = "AmishelltpdnrcekobCdGipOrTyUi" wide //weight: 1
        $x_1_4 = "%c:\\Program Files\\%ls\\" wide //weight: 1
        $x_1_5 = "Moonchild Productions" wide //weight: 1
        $x_1_6 = "%c:\\.RECYCLER\\%ls.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RT_2147780149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RT!MTB"
        threat_id = "2147780149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 8b 45 ?? 05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 8d 85 ?? ?? ?? ?? 33 c9 ba [0-4] e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 33 c9 ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RT_2147780149_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RT!MTB"
        threat_id = "2147780149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PSAPI.DLL" ascii //weight: 1
        $x_1_2 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_3 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_4 = "keybd_event" ascii //weight: 1
        $x_1_5 = "MapVirtualKeyA" ascii //weight: 1
        $x_1_6 = "VkKeyScanExA" ascii //weight: 1
        $x_5_7 = "http://rl.ammyy.com" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RTA_2147780160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RTA!MTB"
        threat_id = "2147780160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 45 ?? 8b 15 ?? ?? ?? ?? 31 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 83 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 03 45 ?? 03 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBJ_2147780371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBJ!MTB"
        threat_id = "2147780371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cOmsVcs.dll" ascii //weight: 1
        $x_5_2 = {03 48 3c 89 4d ?? [0-16] 8b 45 00 83 78 7c 00 0f 84 ?? ?? ?? ?? 8b 4d 00 83 79 78 00 0f 84 ?? ?? ?? ?? 8b 55 00 8b 45 00 8b 4a 78 3b 48 50 0f 83 ?? ?? ?? ?? 8b 55 00 8b 45 ?? 03 42 78 89 45 ?? 8b 4d 0b 8b 55 0a 03 51 1c 89 55 ?? 8b 45 0b 8b 4d 0a 03 48 20 89 4d ?? 8b 55 0b 8b 45 0a 03 42 24 89 45 ec 81 7d ?? ?? ?? ?? ?? 77 ?? 8b 4d 0b 8b 55 ?? 3b 51 10 72 ?? 8b 45 0b 8b 48 14 8b 55 0b 03 4a 10 39 4d ?? 73 ?? 8b 45 0b 8b 4d ?? 2b 48 10 8b 55 0e 8b 45 0a 03 04 8a}  //weight: 5, accuracy: Low
        $x_5_3 = {8a 02 88 45 ?? 0f b6 4d ?? 83 c1 ?? 88 4d ?? 8b 55 ?? [0-16] 0f b6 4d ?? 83 f9 ?? 7c ?? 0f b6 55 ?? 83 fa ?? 7f ?? 0f b6 45 ?? 83 c0 ?? 88 45 ?? 0f b6 4d ?? 83 e9 ?? 88 4d ?? 0f b6 55 ?? 83 c2 ?? 88 55 ?? 0f b6 45 ?? 83 f8 ?? 7c ?? 0f b6 4d ?? 83 f9 ?? 7f ?? 0f b6 55 ?? 83 c2 ?? 88 55 ?? 0f b6 45 ?? 83 e8 ?? 88 45 ?? 0f b6 4d ?? 0f b6 55 ?? 3b ca 74 ?? eb ?? 0f b6 45 ?? 85 c0 75 ?? 8b 4d ?? 8b 41 18}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zbot_SIBL_2147780372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBL!MTB"
        threat_id = "2147780372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 0c d6 8d 4c d6 04 0f c8 89 01 8b 45 ?? 8b 38 31 3c d6 8b 40 04 31 01 4a 89 55 ?? 0f 89}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBB_2147780525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBB!MTB"
        threat_id = "2147780525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 e8 05 89 44 35 ?? 57 8d 45 ?? 50 ff 75 ?? c6 44 35 ?? ?? 8b 35 ?? ?? ?? ?? 6a ff ff d6 85 c0 74 ?? 8b 4d ?? 8b 55 ?? 2b d9 83 eb 05 c6 45 ?? ?? 89 5d ?? e8 ?? ?? ?? ?? 6a 00 6a 05 8d 45 ?? 50 51 6a ff ff d6 85 c0}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 70 3c 8d b4 06 80 00 00 00 57 8b 3e 8b d8 85 ff 74 ?? 83 7e 04 14 76 ?? 8d 34 07 eb ?? 8d 3c 18 8b 46 10 03 c3 eb ?? 3b 08 75 ?? 89 10 83 c7 04 83 c0 04 83 3f 00 75 ?? 83 c6 14 8b 06 85 c0 75 ?? 33 f6 39 8e ?? ?? ?? ?? 75 ?? 89 96 ?? ?? ?? ?? 83 c6 04 83 fe 18}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBG_2147780529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBG!MTB"
        threat_id = "2147780529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "budha.exe" ascii //weight: 1
        $x_1_2 = "kilf.exe" ascii //weight: 1
        $x_10_3 = {8b 16 31 c2 8b 5d ?? 29 da 29 c3 c1 c8 ?? 89 45 ?? 89 5d 00 89 16 83 c6 ?? e2 e5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zbot_SIBV_2147781941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBV!MTB"
        threat_id = "2147781941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 39 5d ?? 76 ?? 8d 64 24 00 8a 0c 33 33 c0 88 4d ?? 8a 14 38 8b 4d ?? d2 e2 8a 4d 02 32 d0 02 d3 32 ca 40 88 4d 02 88 0c 33 83 f8 ?? 72 ?? 33 d2 8b c3 b9 ?? ?? ?? ?? f7 f1 43 8a 14 3a 32 55 02 88 54 33 ?? 3b 5d 00 72 ?? ff 4d 03 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBD2_2147781942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBD2!MTB"
        threat_id = "2147781942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 17 8b 4f ?? 53 b8 ?? ?? ?? ?? 55 8d 64 24 00 8b da c1 eb ?? 8b ea c1 e5 ?? 33 dd 8b e8 c1 ed ?? 83 e5 ?? 03 1c ae 8b e8 33 ea 03 dd 2b cb 8b d9 c1 eb ?? 8b e9 c1 e5 ?? 33 dd 05 ?? ?? ?? ?? 8b e8 83 e5 ?? 03 1c ae 8b e8 33 e9 03 dd 2b d3 85 c0 75 ?? 5d 89 17 89 4f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBB3_2147781943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBB3!MTB"
        threat_id = "2147781943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 89 c7 be [0-16] 8a 1d [0-10] 8a 3e 88 3f 47 46 46 50 8a 06 aa 00 5f ?? 58 e2 [0-10] 83 ec ?? 6a ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 5a 29 c2 52 6a ?? 6a ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 5a 29 c2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBC3_2147781944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBC3!MTB"
        threat_id = "2147781944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 57 89 4d ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 33 c0 89 45 ?? 89 45 [0-10] 8b 4d 00 03 4d 01 33 d2 8a 91 ?? ?? ?? ?? 8b 45 00 03 45 01 33 c9 8a 88 ?? ?? ?? ?? 83 c1 ?? 3b d1 0f 85 ?? ?? ?? ?? 8b 55 00 03 55 01 33 c0 8a 82 ?? ?? ?? ?? 8b 4d 00 03 4d 01 33 d2 8a 91 ?? ?? ?? ?? 83 c2 ?? 3b c2 0f 85 ?? ?? ?? ?? 8b 45 00 03 45 01 33 c9 8a 88 ?? ?? ?? ?? 8b 55 00 03 55 01 33 c0 8a 82 ?? ?? ?? ?? 83 c0}  //weight: 2, accuracy: Low
        $x_2_2 = {3b c8 0f 85 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 33 d2 8a 91 ?? ?? ?? ?? 8b 45 01 03 45 02 33 c9 8a 88 ?? ?? ?? ?? 83 c1 ?? 3b d1 0f 85 ?? ?? ?? ?? 8b 55 01 03 55 02 33 c0 8a 82 ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 45 ?? 8b 4d 01 03 4d 02 33 d2 8a 91 ?? ?? ?? ?? 8b 45 ?? 03 c2 35 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 69 c0 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 03 45 01 8b 55 02 33 c9 8a 8c 10 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 33 4d 0d 8b 55 01 03 55 14 88 8a ?? ?? ?? ?? 81 7d ?? ?? ?? ?? ?? 0f 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBD4_2147781945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBD4!MTB"
        threat_id = "2147781945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b de 8b d2 81 e9 ?? ?? ?? ?? 2b d9 ba ?? ?? ?? ?? bb ?? ?? ?? ?? bf ?? ?? ?? ?? 76 ?? 33 d9 31 3a 09 fb 03 dd 8b 32 7f ?? 09 f3 8a d8 b0 ?? 8a c3 83 c6 ?? 89 32 5b 83 ec ?? 83 c2 ?? 8b da 8b d9 8b cb 83 e9 ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBC5_2147781946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBC5!MTB"
        threat_id = "2147781946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e8 01 f8 89 c5 8a 26 8a 3f 88 e0 88 fb 88 c4 88 df 30 fc 88 27 41 47 46 39 ef 7d ?? 39 d1 7d ?? eb ?? 31 c9 29 d6 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBC6_2147781947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBC6!MTB"
        threat_id = "2147781947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 51 c7 45 ?? ?? ?? ?? ?? eb ?? 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 4d ?? 3b 4d ?? 7f ?? 8b 45 ?? 99 f7 3d ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 8a 08 32 8a ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 88 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBC9_2147781948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBC9!MTB"
        threat_id = "2147781948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 85 c0 75 ?? 90 58 2b f0 8b d8 50 51 8b c7 57 8b 08 5f e8 ?? ?? ?? ?? 33 c1 8b 06 fe cd 33 c1 8b c8 46 88 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBC11_2147781949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBC11!MTB"
        threat_id = "2147781949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 58 53 57 8b d8 53 85 c0 75 ?? 90 58 2b f0 8b d8 50 51 8b c7 57 8b 08 5f e8 ?? ?? ?? ?? 41 33 c0 8b 06 49 33 c1 8b c8 46 88 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBB6_2147781950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBB6!MTB"
        threat_id = "2147781950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 89 c7 be ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 49 8a 1d ?? ?? ?? ?? 0f 31 50 8a 3e 88 3f 47 46 46 50 8a 06 aa 00 5f ff 58 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {66 81 3f 4d 5a 75 ?? 89 fa 03 57 3c 66 81 3a 50 45 75 ?? 89 55 ?? 8b 42 78 03 45 08 89 45 ?? 8b 40 20 03 45 08 89 45 ?? 31 c9 8b 55 03 3b 4a 18 7d 3a 8b 5d 04 8b 1c 8b 03 5d 08 ff 75 0c 53 e8 ?? ?? ?? ?? 83 f8 01 74 ?? 41 eb ?? 8b 45 03 8b 40 24 03 45 08 31 db 66 8b 1c 48 8b 45 03 8b 40 1c 03 45 08 8b 04 98 03 45 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBG3_2147781953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBG3!MTB"
        threat_id = "2147781953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "budha.exe" ascii //weight: 1
        $x_1_2 = {6b 00 69 00 6c 00 66 00 [0-5] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6b 69 6c 66 [0-5] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_10_4 = {2b ce 3b c8 74 ?? ff 45 ?? 83 7d 01 ?? 7c ?? 83 7d 01 ?? 0f 84 ?? ?? ?? ?? 80 3e ?? 74 ?? 80 7e ?? ?? 74 ?? c1 e0 ?? 50 6a ?? ff 75 ?? ff 15 ?? ?? ?? ?? 89 45 ?? 3b c3 0f 84 ?? ?? ?? ?? 8b 7d ?? 8b 45 ?? 8b 40 ?? 8b d7 33 c9 83 e7 ?? c1 e2 ?? 41 89 5d ?? 83 ff ?? 76 ?? 31 04 8e 8b 7d 12 41 c1 ef ?? 3b cf 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zbot_SIBD14_2147781954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBD14!MTB"
        threat_id = "2147781954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 07 83 c7 ?? 8b f7 8b de 03 f8 8b d7 4a 2b c8 83 e9 ?? 52 ba ?? ?? ?? ?? 89 0a 89 7a ?? 5a 8a 07 8a 26 02 25 ?? ?? ?? ?? 32 c4 88 07 3b f2 74 ?? 46 47 49 75 ?? eb ?? 8b f3 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBE3_2147781955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBE3!MTB"
        threat_id = "2147781955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8b d8 85 c0 90 58 2b f0 50 8b d8 51 8b 07 8b c8 40 8b 06 8a e9 32 c5 fe c1 88 07 46}  //weight: 1, accuracy: Low
        $x_1_2 = {50 8b d8 85 c0 90 58 2b f0 50 8b d8 51 8b 07 8b c8 40 e8 ?? ?? ?? ?? 47 4b 8b c3 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AB_2147781973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AB!MTB"
        threat_id = "2147781973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 45 fc d3 9e 08 00 8b 55 0c 03 55 f4 0f b6 02 89 45 f8 c7 45 fc d3 9e 08 00 8b 4d 08 03 4d f4 8a 55 f8 88 11}  //weight: 10, accuracy: High
        $x_3_2 = "Toolhelp32ReadProcessMemory" ascii //weight: 3
        $x_3_3 = "GkzCAoexmAcXCg0hL" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_EP_2147783575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.EP!MTB"
        threat_id = "2147783575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Univsamurinercanx" ascii //weight: 1
        $x_1_2 = "m32mxFVTbk" ascii //weight: 1
        $x_1_3 = "qxwedamrdaemx" ascii //weight: 1
        $x_1_4 = "kmscmefdwqw" ascii //weight: 1
        $x_1_5 = "Deanumsenmawzc" ascii //weight: 1
        $x_1_6 = "erwrdesxqw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBK_2147785236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBK!MTB"
        threat_id = "2147785236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 72 63 2e [0-5] 2e 62 79}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\log.txt" ascii //weight: 1
        $x_1_3 = "kiber_soldiers" ascii //weight: 1
        $x_1_4 = "!shutup" ascii //weight: 1
        $x_1_5 = "!shutdown" ascii //weight: 1
        $x_1_6 = "!P2PINFECT" ascii //weight: 1
        $x_1_7 = "!LOAD" ascii //weight: 1
        $x_1_8 = "\\software\\Morpheus" ascii //weight: 1
        $x_1_9 = "\\software\\Xolox" ascii //weight: 1
        $x_1_10 = "\\software\\Kazaa" ascii //weight: 1
        $x_1_11 = "\\software\\Shareaza" ascii //weight: 1
        $x_1_12 = "\\software\\LimeWire" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_Zbot_SIBT_2147785237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBT!MTB"
        threat_id = "2147785237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 3e 8b 5e 04 e8 ?? ?? ?? ?? 03 c0 89 45 ?? e8 ?? ?? ?? ?? 8b 4d ?? 40 8b 75 ?? 89 45 ?? c7 45 ?? ?? ?? ?? ?? 8b 01 89 45 ?? 8b 41 ?? 89 45 ?? 8b 41 ?? 89 45 ?? 8b 41 ?? 89 45 ?? ff 15 ?? ?? ?? ?? 8b cf 8b c7 c1 e9 ?? 03 4d ?? c1 e0 ?? 03 45 ?? 56 ff 75 ?? 33 c8 8d 04 3e ff 75 ?? 33 c8 2b d9 53 e8 ?? ?? ?? ?? 33 c9 2b f8 8b 45 ?? 41 2b c8 83 c4 ?? 03 f1 ff 4d ?? 75 ?? 8b 75 ?? 89 3e 5f 89 5e 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBA6_2147785238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBA6!MTB"
        threat_id = "2147785238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 02 03 05 ?? ?? ?? ?? 8b 4d ?? 03 0d 00 89 01 8b 15 00 81 c2 ?? ?? ?? ?? 8b 45 01 03 05 00 33 10 8b 4d 01 03 0d 00 89 11 a1 00 83 c0 04 a3 00 8b 0d 00 3b 4d ?? 73 ?? 8b 55 01 03 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBE12_2147785239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBE12!MTB"
        threat_id = "2147785239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 53 85 c0 75 ?? 90 58 2b f0 8b d8 50 51 8b c7 57 8b 08 5f e8 ?? ?? ?? ?? 33 c1 8b 06 fe cd 33 c1 8b c8 46 88 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBD16_2147785240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBD16!MTB"
        threat_id = "2147785240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 f6 8b 4c 24 ?? 8a 0c 0e 8a d1 c0 ea ?? 80 e1 ?? 80 fa ?? 0f 9e c3 fe cb 80 e3 ?? 80 c3 ?? 02 da 80 f9 ?? 0f 9e c2 fe ca 80 e2 ?? 80 c2 ?? 02 d1 88 18 88 50 01 46 83 c0 ?? 83 fe ?? 72}  //weight: 10, accuracy: Low
        $x_5_2 = {8b 10 8b f2 c1 ee ?? 33 f2 69 f6 ?? ?? ?? ?? 03 f1 89 70 ?? 83 c0 ?? 41 3d ?? ?? ?? ?? 7c ?? 89 0d ?? ?? ?? ?? 5e a1 06 3d ?? ?? ?? ?? 0f 8c ?? ?? ?? ?? ?? ?? 33 d2 be ?? ?? ?? ?? 8b ca 8b 04 8d ?? ?? ?? ?? 33 04 8d ?? ?? ?? ?? 23 c6 33 04 8d 0e 8b f8 d1 e8 83 e7 ?? 33 04 bd ?? ?? ?? ?? 33 04 8d ?? ?? ?? ?? 42 89 04 8d 0e 81 fa ?? ?? ?? ?? 7c ?? 81 fa ?? ?? ?? ?? 7d ?? 8d 0c 95 0e 8b 01 33 41 ?? 23 c6 33 01 8b f8 83 e7 ?? 8b 3c bd 11 33 b9 ?? ?? ?? ?? d1 e8 33 f8 89 39 83 c1 ?? 81 f9 04 7c ?? 8b 0d 04 a1 0e 33 c1 23 c6 33 c1 8b c8 d1 e8 83 e1 ?? 33 04 8d 11 ?? 33 05 ?? ?? ?? ?? ?? a3 04 33 c0}  //weight: 5, accuracy: Low
        $x_5_3 = {33 c0 8b 0c 85 ?? ?? ?? ?? 40 a3 ?? ?? ?? ?? 8b c1 c1 e8 ?? 33 c8 8b c1 25 ?? ?? ?? ?? c1 e0 ?? 33 c8 8b c1 25 ?? ?? ?? ?? c1 e0 ?? 33 c8 8b c1 c1 e8 ?? 33 c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zbot_SIBA7_2147785241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBA7!MTB"
        threat_id = "2147785241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 08 03 4d ?? 8b 55 ?? 89 0a 8b 45 ?? 8b 08 89 4d ?? 8b 15 ?? ?? ?? ?? 52 8b 45 03 50 e8 ?? ?? ?? ?? 83 c4 08 89 45 ?? 8b 4d 02 8b 55 07 89 11 8b 45 00 83 c0 ?? 89 45 00 8b 4d 00 3b 4d ?? 0f 83 ?? ?? ?? ?? [0-26] 8b 55 00 81 c2 ?? ?? ?? ?? 89 15 04 [0-10] 8b 45 ?? 03 45 00 89 45 01 [0-26] 8b 4d 01 89 4d 02 8b 15 04 [0-16] 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBE19_2147785242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBE19!MTB"
        threat_id = "2147785242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 ed ba 00 00 00 00 01 fa b8 ?? ?? ?? ?? 01 f8 89 c7 89 44 24 ?? be ?? ?? ?? ?? 01 c6 80 38 ?? 75 ?? 8a 0a 88 08 42 81 fd ?? ?? ?? ?? 7d ?? 8a 0a c0 e1 ?? 08 08 42 45 40 39 c6 75}  //weight: 1, accuracy: Low
        $x_1_2 = {5a 31 c9 8a 2f 32 2a 88 2f fe c1 42 80 f9 ?? 75 ?? 31 c9 83 ea ?? 47 39 f8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBC21_2147785243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBC21!MTB"
        threat_id = "2147785243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 31 c9 8a 2f 32 2a 88 2f fe c1 42 80 f9 ?? 75 ?? 31 c9 83 ea ?? 47 39 f8 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 5d 00 83 eb ?? be ?? ?? ?? ?? 29 f3 89 1c 24 57 be ?? ?? ?? ?? 01 de b9 ?? ?? ?? ?? f3 a4 be ?? ?? ?? ?? 01 de b9 ?? ?? ?? ?? f3 a4 5f be ?? ?? ?? ?? 85 f6 74 ?? ba ?? ?? ?? ?? 01 fa b8 ?? ?? ?? ?? 01 f8 89 c7 89 44 24 ?? be ?? ?? ?? ?? 01 c6 80 38 ?? 75 ?? 8a 0a 88 08 42 40 39 c6 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AAO_2147787353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AAO!MTB"
        threat_id = "2147787353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a c1 80 fa 08 72 0e 56 0f b6 f2 c1 ee 03 80 c2 f8 4e 75 fa 5e 8a ca d2 c0 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8a 06 2a 45 ff 8a 56 02 8b 4e 10 8a 5e 14 fe c8 32 d0 8a c2 32 45 fe 85 c9 74 08 84 db 0f 85 a0 00 00 00 33 c0 85 c0 74 09 32 55 fd 8a 0f ff d0 88 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBE23_2147787620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBE23!MTB"
        threat_id = "2147787620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 f8 89 c7 89 44 24 ?? be ?? ?? ?? ?? 01 c6 80 38 00 75 ?? 8a 0a 88 08 42 40 39 c6 75 ?? 5a 31 c9 8a 2f 32 2a 88 2f fe c1 42 80 f9 ?? 75 ?? 31 c9 83 ea ?? 47 39 f8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBE15_2147787690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBE15!MTB"
        threat_id = "2147787690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 15 30 00 00 00 8b 52 0c 8b 52 14 8b 72 28 b9 ?? ?? ?? ?? 33 ff 33 c0 ac 3c ?? 7c ?? 2c ?? c1 cf ?? 03 f8 e2 ?? 81 ff ?? ?? ?? ?? 8b 42 10 8b 12 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f2 2b c8 8a 14 01 30 10 40 4e 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SD_2147788362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SD!MTB"
        threat_id = "2147788362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 49 00 03 f8 8b ff 8b 17 8b 4d ?? 81 f1 9d 10 e6 3d 03 f9 8b 07 c1 c0 05 83 e0 05 03 d0 4e 89 13 b9 4e 2e dc 06 81 f1 4a 2e dc 06 03 d9 85 f6 0f 84 ?? ?? ?? ?? 8b 17 8b 4d fc 81 e9 f5 f0 2b ee 03 f9 8b 07 c1 c0 05 83 e0 05 03 d0 4e 89 13 b9 40 00 00 00 c1 c1 1c 03 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBD25_2147794044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBD25!MTB"
        threat_id = "2147794044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 00 00 00 00 b8 ?? ?? ?? ?? 30 07 41 47 39 f1 30 07 41 47 39 f1 72 ?? 58 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBA9_2147794045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBA9!MTB"
        threat_id = "2147794045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 03 4d ?? 8b 11 03 55 00 8b 45 08 03 45 00 89 10 [0-10] 8b 4d 00 81 c1 ?? ?? ?? ?? 8b 55 08 03 55 00 33 0a 8b 45 08 03 45 00 89 08 [0-10] 8b 45 00 83 c0 04 89 45 00 8b 4d 00 3b 4d 0c 73 ?? [0-16] 83 7d 00 00 8b 4d 08 03 4d 00 8b 11 03 55 00 8b 45 08 03 45 00 89 10 [0-10] 8b 4d 00 81 c1 05 8b 55 08 03 55 00 33 0a 8b 45 08 03 45 00 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBA10_2147794046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBA10!MTB"
        threat_id = "2147794046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 03 55 ?? 8b 02 03 45 00 8b 4d 08 03 4d 00 89 01 [0-10] 8b 55 00 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? [0-16] 8b 4d 08 03 4d 00 8b 11 33 15 06 8b 45 08 03 45 00 89 10 8b 45 00 83 c0 04 89 45 00 8b 4d 00 3b 4d 0c 73 ?? [0-10] 8b 55 08 03 55 00 8b 02 03 45 00 8b 4d 08 03 4d 00 89 01 [0-10] 8b 55 00 81 c2 05 89 15 06 [0-16] 8b 4d 08 03 4d 00 8b 11 33 15 06 8b 45 08 03 45 00 89 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBA11_2147794047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBA11!MTB"
        threat_id = "2147794047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 4d 0c 0f 83 ?? ?? ?? ?? [0-16] 8b 55 ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 45 08 03 45 02 8b 08 03 4d 02 8b 55 08 03 55 02 89 0a [0-16] 8b 0d 04 89 4d ?? 8b 55 0a 89 55 ?? 8b 45 0c 89 45 ?? 83 7d 02 ?? 8b 4d 08 03 4d 02 8b 11 33 55 0e 8b 45 08 03 45 02 89 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SIBD26_2147794048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SIBD26!MTB"
        threat_id = "2147794048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b d3 56 51 8b 07 51 8b c8 48 8b 06 33 c1 51 56 8b f7 88 06 5e 46 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_YTL_2147794453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.YTL!MTB"
        threat_id = "2147794453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 fb 8b 7c 24 08 03 7c 24 08 2b 7c 24 08 31 fb 33 5c 24 ?? 89 5c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {68 01 00 00 00 8d 44 24 ?? 50 8b 5c 24 ?? 03 5c 24}  //weight: 1, accuracy: Low
        $x_1_3 = "KsdnYYe2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AR_2147795104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AR!MTB"
        threat_id = "2147795104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 13 03 d6 b9 61 21 bc 4c 81 f1 65 21 bc 4c 03 d9 c1 c2 0e 89 55 e8 03 c5 50 e8 ?? ?? ?? ?? 53 5a 58 2b c5 8b 4d bc c1 c9 1b 03 c8 3b c8 0f 85 8c 00 00 00 2b c8 48 3b c1 75 c5}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 5d 36 d3 84 81 f1 59 36 d3 84 03 f9 8b 0f 8b 45 cc c1 c0 0c 3b c8 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AM_2147795105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AM!MTB"
        threat_id = "2147795105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d 0c 8b 07 33 d2 89 45 08 33 db 8a 55 0b 8a 5d 0a 8b 14 95 f8 bb 41 00 33 14 9d f8 bf 41 00 33 db 8a dc 25 ff 00 00 00 33 14 9d f8 c3 41 00 33 14 85 f8 c7 41 00 89 17 83 c7 04 49 75 c4 ff 45 14 83 45 0c 20 8b 45 14 3b 86 d0 03 00 00 7c a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AL_2147795106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AL!MTB"
        threat_id = "2147795106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 5c 0d a8 8b 45 d4 30 1c 10 41 83 f9 13 76 02 33 c9 42 3b 56 04 72 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 39 88 14 31 41 3b c8 72 f5 83 65 e4 00 33 c0 66 3b 43 06 73 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AL_2147795106_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AL!MTB"
        threat_id = "2147795106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {28 13 43 c1 ea 08 41 83 f9 04 75 0a ba 72 c6 0e de b9 00 00 00 00 81 fb 9f fa 40 00 72}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DF_2147796161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DF!MTB"
        threat_id = "2147796161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {90 8b 55 fc 8a 1c 11 80 c3 7a 88 1c 11 8b 55 fc 8a 1c 11 80 c3 fd 88 1c 11 8b 55 fc 80 04 11 03 90 8b 55 fc 8a 1c 11 80 f3 19 88 1c 11 41 3b c8 7c ce}  //weight: 1, accuracy: High
        $x_1_2 = {8a 0c 28 80 f1 80 88 0c 28 8b 4c 24 10 40 3b c1 72 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DG_2147796539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DG!MTB"
        threat_id = "2147796539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d f4 83 c1 01 89 4d f4 8b 55 f4 3b 55 f8 7d 69 8b 45 10 3b 45 fc 7f 0b 8b 4d 10 03 4d fc 89 4d f0 eb 09 8b 55 10 2b 55 fc 89 55 f0 8b 45 08 03 45 f4 0f be 08 8b 75 fc 33 75 10 83 c6 58 8b 45 f0 99 f7 fe 33 ca 8b 55 08 03 55 f4 88 0a 83 7d fc 3a 7e 09 c7 45 fc 00 00 00 00 eb 1a 83 7d 10 5a 7e 0b 8b 45 fc 83 c0 02 89 45 fc eb 09 8b 4d fc 83 c1 03 89 4d fc eb 86}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DJ_2147796822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DJ!MTB"
        threat_id = "2147796822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qfF44DPOVLUmyodKx4pgjVDx2uBikWAqb8RQ7NLl46zuDBbK" ascii //weight: 1
        $x_1_2 = "zbgeH34RUsjNuL4apqwnCVRhtUwbxVSHLoNjcr8pLgwk71yyTLT3DokEdicU2xVxuhc4KkiOp9P6kN" ascii //weight: 1
        $x_1_3 = "3fvGTVBvMOoFrIDrLp04Qh1vvXiyRWM93POFZy94H697NEC8MKbMOoDy1b5UDumtWHdLZryXTNJagl" ascii //weight: 1
        $x_1_4 = "4KOKnHoSsIYp9PgEENoZ1Pi71sqi62EitB2DHnpw9PT0fRpEB58MEAcbAxdSjUYfx" ascii //weight: 1
        $x_1_5 = "sG6tuzSUAKNM2H4Nt1E1vrNhrkOgqkR6zohY8hOZBNLcKXmhGMvon0J8DU2Wv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DM_2147796825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DM!MTB"
        threat_id = "2147796825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 d4 f2 e0 14 85 c0 75 06 ff 15 1c f1 e0 14 8b 4c 24 08 69 c0 fd 43 03 00 2b 4c 24 04 05 c3 9e 26 00 a3 d4 f2 e0 14 41 33 d2 f7 f1 8b c2 03 44 24 04}  //weight: 1, accuracy: High
        $x_1_2 = {39 45 f8 76 1d 8a c8 02 c9 a8 01 75 09 b2 f6 2a d1 00 14 38 eb 06 80 c1 07 00 0c 38 40 3b 45 f8 72 e3}  //weight: 1, accuracy: High
        $x_1_3 = "outpost.exe" ascii //weight: 1
        $x_1_4 = "wsnpoema.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DM_2147796825_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DM!MTB"
        threat_id = "2147796825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe c3 36 8a 94 2b 00 fc ff ff 02 c2 36 8a 8c 28 00 fc ff ff 36 88 8c 2b 00 fc ff ff 36 88 94 28 00 fc ff ff 02 ca 36 8a 8c 29 00 fc ff ff 30 0e 46 4f 75 cc}  //weight: 1, accuracy: High
        $x_1_2 = "DecryptMessage" ascii //weight: 1
        $x_1_3 = "HOST2:80.85.84.79" ascii //weight: 1
        $x_1_4 = "https://ip4.seeip.org" ascii //weight: 1
        $x_1_5 = "194.109.206.212" ascii //weight: 1
        $x_1_6 = "131.188.40.189" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DO_2147796943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DO!MTB"
        threat_id = "2147796943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 db 75 07 8b 1e 83 ee fc 11 db 11 c9 eb 52 29 c9 83 e8 03 72 11 c1 e0 08 8a 06 46 83 f0 ff 74 75 d1 f8 50 5d eb 0b 01 db 75 07 8b 1e 83 ee fc 11 db 72 cc}  //weight: 1, accuracy: High
        $x_1_2 = {8a 06 46 88 07 47 01 db 75 07 8b 1e 83 ee fc 11 db 72 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DO_2147796943_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DO!MTB"
        threat_id = "2147796943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 08 bb 0a 00 00 00 8b 4d 0c c1 e9 02 ba 00 00 00 00 8b 45 0c c1 e8 02 2b c1 50 f7 f3 42 42 29 16 33 d2 58 f7 f3 03 14 24 52 81 04 24 21 ec 30 45 5a 31 16 83 c6 04 e2 d4}  //weight: 1, accuracy: High
        $x_1_2 = {31 19 ad 58 47 22 ed 30 ba f5 12 44 61 07 12 25 55 09 ad 30 13 53 6d 30 45 2d 87 32 13 55 ef 58 45 31 ed 70 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DN_2147797055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DN!MTB"
        threat_id = "2147797055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bf f5 b2 36 f8 31 ee 55 28 3a 1a 5e 3f a3 b2 30 34 03 30 99 08 f3 f2 9d e1 f2}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Users\\Frank\\Desktop\\khHREbPj.exe" ascii //weight: 1
        $x_1_3 = "C:\\Users\\admin\\Downloads\\ffengh.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DQ_2147797672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DQ!MTB"
        threat_id = "2147797672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b4 4a 40 00 30 47 40 00 00 02 00 05 4b ff ff 00 19 28 58 ff 01 00 6b 10 00 e7 80 0c 00 0b b0 00 0c 00 31 78 ff 35 58 ff 00 2b 6c 0c 00 6b 10 00 e7 f5 01 00 00 00 28 58 ff 01 00 6b 14 00 e7 80 0c 00 0b b0 00 0c 00 23 54 ff 4f 00 00 2f 54 ff 35 58 ff 00 14 6c 0c 00 6b 14 00 e7 f5 01 00 00 00 6c 78 ff}  //weight: 1, accuracy: High
        $x_1_2 = {c7 40 ff 3e 4c ff fd c7 44 ff 0a c0 00 08 00 32 06 00 48 ff 44 ff 40 ff 00 28 04 4c ff 04 50 ff 10 04 07 1a 00 f5 07 00 00 00 80 0c 00 6c 4c ff 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DR_2147797673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DR!MTB"
        threat_id = "2147797673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 5d fe 8a c8 8a 45 ff 8a d4 80 f1 da 80 f2 79 80 f3 31 34 38 80 f9 e9 75 0d 80 fa 40 75 08 84 db 75 04 84 c0 74 0d 8b 45 fc 03 c6 89 45 fc 83 f8 ff 76 cc}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 0c 8d 46 1c 2b ce bf 01 01 00 00 8a 14 01 88 10 40 4f 75 f7 8d 86 1d 01 00 00 be 00 01 00 00 8a 14 08 88 10 40 4e 75 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DS_2147797674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DS!MTB"
        threat_id = "2147797674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 75 08 bb 0a 00 00 00 8b 4d 0c c1 e9 02 ba 00 00 00 00 8b 45 0c c1 e8 02 2b c1 50 f7 f3 42 42 29 16 33 d2 58 f7 f3 03 14 24 52 81 04 24 21 ec 30 45 5a 31 16 83 c6 04 e2 d4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DV_2147797676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DV!MTB"
        threat_id = "2147797676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Save.dll" ascii //weight: 1
        $x_1_2 = "GetTempPathW" ascii //weight: 1
        $x_1_3 = "c:\\cryptor\\cryptordll\\bin\\json.h" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "OutputDebugStringW" ascii //weight: 1
        $x_1_6 = "Bit Sheover Totalfather" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DI_2147797751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DI!MTB"
        threat_id = "2147797751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 ac 81 f6 41 08 8b 24 0f b6 0e 46 46 81 f6 41 08 8b 24 89 75 ac b8 10 00 00 00 c1 c0 03 3b c8 0f 82 a9 07 00 00 2b c8 03 c9 8b 55 ec c1 c2 1b 03 d1 03 d1 c1 c2 05 89 55 ec 33 c0 3b c8 75 bf}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Users\\admin\\Downloads\\wefujn.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AQ_2147797995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AQ!MTB"
        threat_id = "2147797995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 db 8a da 80 f3 08 80 38 00 74 06 38 18 74 02 30 18 40 42 3b 15 [0-4] 76}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AQ_2147797995_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AQ!MTB"
        threat_id = "2147797995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 08 bb 0a 00 00 00 8b 4d 0c c1 e9 02 33 d2 8b 45 0c c1 e8 02 2b c1 50 f7 f3 83 c2 02 29 16 33 d2 58 f7 f3 03 14 24 81 c2 a0 82 f9 45 31 16 83 c6 04 e2 d9}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\Y9DfPswRr.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DB_2147797996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DB!MTB"
        threat_id = "2147797996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\klemmd\\AppData\\Local\\Temp\\Temp1_Remit_ath ru.zip\\fax.exe" ascii //weight: 1
        $x_1_2 = "C:\\SiF4PIlK.exe" ascii //weight: 1
        $x_1_3 = "C:\\Users\\admin\\Downloads\\2d7adc32bae06be4fc17ca7f15d1a3d9.virus.exe" ascii //weight: 1
        $x_1_4 = "C:\\Users\\george\\Desktop\\foxupdater.exe" ascii //weight: 1
        $x_1_5 = "C:\\Users\\r.vult\\AppData\\Local\\Temp\\d89fb063517126d16cfe3bfd01205669.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BB_2147798301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BB!MTB"
        threat_id = "2147798301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 43 35 00 59 00 00 47 83 ee ff 81 f1 ?? ?? ?? ?? 49 41 e9 2e}  //weight: 5, accuracy: Low
        $x_5_2 = {84 00 43 00 8b 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 33 ce 89 35 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? f7 da 89 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 e1 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 49 89 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_ADT_2147798615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.ADT!MTB"
        threat_id = "2147798615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 55 fc b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72 e3}  //weight: 10, accuracy: Low
        $x_1_2 = "fekovimofojituzuwivuwubajiyofori" ascii //weight: 1
        $x_1_3 = "bomgpiaruci.iwa" ascii //weight: 1
        $x_1_4 = "Copyrighz (C) 2021, fudkagat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_FNF_2147798717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.FNF!MTB"
        threat_id = "2147798717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {a1 00 14 46 00 31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0}  //weight: 10, accuracy: High
        $x_1_2 = "fekovimofojituzuwivuwubajiyofori" ascii //weight: 1
        $x_1_3 = "peraleyuwawusogeyodotu" ascii //weight: 1
        $x_1_4 = "bomgpiaruci.iwa" ascii //weight: 1
        $x_1_5 = "Copyrighz (C) 2021, fudkagat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_FL_2147798718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.FL.MTB"
        threat_id = "2147798718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 e0 8b 45 f4 01 d0 0f b6 08 8b 45 f4 83 e0 1f 0f b6 44 05 8e 89 c3 8b 55 e4 8b 45 f4 01 d0 31 d9 89 ca 88 10 83 45 f4 01 81 7d f4 ff af 00 00 76 cd}  //weight: 10, accuracy: High
        $x_10_2 = {c7 44 24 10 00 00 00 00 8d 45 88 89 44 24 0c c7 44 24 08 00 b0 00 00 8b 45 e4 89 44 24 04 8b 45 ec 89 04 24 e8 cb 00 00 00 83 ec 14 8b 45 ec 89 04 24}  //weight: 10, accuracy: High
        $x_1_3 = "mal.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DD_2147805261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DD!MTB"
        threat_id = "2147805261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hfdfjdk.exe" ascii //weight: 1
        $x_1_2 = "ce-cloud.com" ascii //weight: 1
        $x_1_3 = "images/notech.exe" ascii //weight: 1
        $x_1_4 = "ddjienn.exe" ascii //weight: 1
        $x_1_5 = "Updates downloader" ascii //weight: 1
        $x_1_6 = "C:\\yQE6ncko.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DU_2147805265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DU!MTB"
        threat_id = "2147805265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 c1 c1 c0 f0 c0 35 c1 10 c0 45 c0 c0 10 31 30 20 35 31 20 c1 c3 8b 31 8b c1 20 35 f0 c0 f0 20 c0 31 30 10 31 20 31 c0 31 8b f0 c0 30 35 45 30 c1 30 30 8b 30 c3}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Users\\george\\Desktop\\dawid.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_2147806113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.rbnd!MTB"
        threat_id = "2147806113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "rbnd: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 70 60 8b 45 fc 83 c0 20 03 f0 8b 3e 83 ee 0c 8b 06 03 7d fc 89 45 f4 83 ee 14 33 d2 8b 5d 0c c3}  //weight: 10, accuracy: High
        $x_10_2 = {89 15 43 29 06 29 42 33 30 43 03 42 00 36 50}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_2147806236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.wqky!MTB"
        threat_id = "2147806236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "wqky: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 06 33 c1 e8 7b 00 00 00 c3}  //weight: 10, accuracy: High
        $x_10_2 = {8b c8 88 07 83 c6 01 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_2147806237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.svfs!MTB"
        threat_id = "2147806237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "svfs: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 30 8b 45 fc 83 c6 20 03 f0 8b 3e 83 ee 0c 8b 06 03 7d fc 89 45 f4 83 ee 14 33 d2 8b 5d 0c c3}  //weight: 10, accuracy: High
        $x_10_2 = {83 c6 23 46 b9 02 00 00 00 f7 e1 8b c8 8b 06 03 c8 8b 45 fc 03 c8 0f b7 01 83 ee 24 8b 4e 1c 8d 04 81 8b 4d fc 8b 04 01 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DP_2147806400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DP!MTB"
        threat_id = "2147806400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 53 8b 5d 94 85 df c1 c3 18 8b 0b 8b 45 80 85 c3 c1 c8 02 3b c8 75 cb}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0e 03 cb b8 00 40 00 00 c1 c0 14 03 f0 c1 c1 08 89 4d 94 03 d5 52 e8 ?? ?? ?? ?? 56 59 5a 2b d5 8b 45 a8 85 c7 c1 c0 16 03 c2 3b c2 0f 85 ?? ?? ?? ?? 2b c2 4a 3b d0 75 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zbot_2147807960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.rmwh!MTB"
        threat_id = "2147807960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "rmwh: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 06 8a e9 32 c5 fe c1}  //weight: 10, accuracy: High
        $x_10_2 = {8b 3e 83 ee ?? 8b 06 03 7d fc 89 45 f4 83 ee ?? 33 d2 8b 5d 0c c3}  //weight: 10, accuracy: Low
        $x_10_3 = {53 23 0e 30 48 61 96 8a 54 fb a1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Zbot_GLM_2147808277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GLM!MTB"
        threat_id = "2147808277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f4 33 45 f0 33 f0 3b f7 75 07 be 4f e6 40 bb eb 0b 85 f3 75 07 8b c6 c1 e0 10 0b f0 89 35 c8 de 40 00 f7 d6 89 35 cc de 40 00 5e 5f 5b c9 c3}  //weight: 10, accuracy: High
        $x_1_2 = "LDuhywso.exe" ascii //weight: 1
        $x_1_3 = "ormwnrZK.exe" ascii //weight: 1
        $x_1_4 = "fBoQqsyz.exe" ascii //weight: 1
        $x_1_5 = "conwur.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_MMW_2147808280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.MMW!MTB"
        threat_id = "2147808280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 31 35 b5 50 40 00 8b 14 24 01 f2 8b 0c 24 13 0d ?? ?? ?? ?? 8b 04 24 01 f0 8b 14 24 01 c2 29 35 ?? ?? ?? ?? 29 f6}  //weight: 10, accuracy: Low
        $x_1_2 = "szgfw.exe" ascii //weight: 1
        $x_1_3 = "hwiwjgtqkyrjleqld" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DKL_2147808281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DKL!MTB"
        threat_id = "2147808281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 38 03 fe 33 db b8 ?? ?? ?? ?? 2d 8d 8b ec 55 8b 0f 8b 55 ec 81 c2 ?? ?? ?? ?? 33 ca 23 c8 3b cb 0f 85 4e 0e 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {89 16 b9 8d 15 55 fc 81 f1 ?? ?? ?? ?? 03 f1 ba ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 03 da 81 c3 ?? ?? ?? ?? 89 5d a0 c1 c6 0a 89 b5 ?? ?? ?? ?? 5e 5b 5f c3}  //weight: 10, accuracy: Low
        $x_1_3 = "ftc.exe" ascii //weight: 1
        $x_1_4 = "Kramivo" ascii //weight: 1
        $x_1_5 = "Jkadsuxicni" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_CHA_2147808318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.CHA!MTB"
        threat_id = "2147808318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\elodier\\AppData\\Local\\Temp\\Rar$EX00.373\\Avis_de_Paiement.exe" ascii //weight: 1
        $x_1_2 = "C:\\sample.exe" ascii //weight: 1
        $x_1_3 = "C:\\Users\\admin\\Downloads\\file016_ieupdate.exe" ascii //weight: 1
        $x_1_4 = "Heepil" ascii //weight: 1
        $x_1_5 = "C:\\Users\\r.vult\\AppData\\Local\\Temp\\678c93c84bc7544da0a95036deb0f76f.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_2147808590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.simd!MTB"
        threat_id = "2147808590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "simd: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 0e 8b 45 a8 c1 c0 0c 03 f0 8b 16 c1 c2 03 83 e2 09 03 ca 4b 89 0f b8 ?? ?? ?? ?? 35 fe 0c cd f5 03 f8 85 db 75 b0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_VHO_2147808591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.VHO!MTB"
        threat_id = "2147808591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 7d 70 8b 45 60 8b 40 60 8b d7 33 c9 83 e7 fc c1 e2 02 41 89 5d 4c 83 ff 04 76 0e 31 04 8e 8b 7d 70 41 c1 ef 02 3b cf 72 f2}  //weight: 10, accuracy: High
        $x_1_2 = "kilf1.exe" ascii //weight: 1
        $x_1_3 = "budha.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RQIJ_2147808775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RQIJ!MTB"
        threat_id = "2147808775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 03 8b 70 60 8b 45 fc 83 c0 20 03 f0 8b 3e 83 ee ?? 8b 06 03 7d fc 89 45 f4 83 ee ?? 33 d2 8b 5d 0c c3}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 fc 03 c8 0f b7 01 83 ee ?? 8b 4e 1c 8d 04 81 8b 4d fc 8b 04 01}  //weight: 10, accuracy: Low
        $x_1_3 = "vcxtR4oeM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_ZMZC_2147808928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.ZMZC!MTB"
        threat_id = "2147808928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 06 8a e9 32 c5 fe c1}  //weight: 10, accuracy: High
        $x_10_2 = {8b 50 0c 03 f2 03 fe 2b c0 2b d2 0b d0 ac c1 e2 07 d0 e8 72 f6}  //weight: 10, accuracy: High
        $x_1_3 = "LPTlFnmn.exe" ascii //weight: 1
        $x_1_4 = "8bsO07Aa.exe" ascii //weight: 1
        $x_1_5 = "KFCXi7de.exe" ascii //weight: 1
        $x_1_6 = "Wm5_ofJU.exe" ascii //weight: 1
        $x_1_7 = "POFnKJRj.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GLL_2147808930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GLL!MTB"
        threat_id = "2147808930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b fe 33 30 8b ff 8b 75 b8 81 c6 ?? ?? ?? ?? ba ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 23 f2 b9 ?? ?? ?? ?? c1 c9 05 b8 ?? ?? ?? ?? 35 ?? ?? ?? ?? e9 0b 01 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {33 07 33 c1 08 ff 8b ff 8b 16 8b 4d a0 81 f1 03 d4 f4 e4 03 f1 e9 f2 01 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_QLM_2147808931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.QLM!MTB"
        threat_id = "2147808931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://www.besthotel360.com:1219/001/puppet.Txt" ascii //weight: 2
        $x_2_2 = "VirtualProtect" ascii //weight: 2
        $x_2_3 = "VirtualAlloc" ascii //weight: 2
        $x_2_4 = "HTTP/1.1" ascii //weight: 2
        $x_2_5 = "HTTP/1.0" ascii //weight: 2
        $x_2_6 = "PryJEN1Mh1iFYPryJEN1Mh1iFYPryJEN1Mh1iFY" ascii //weight: 2
        $x_2_7 = "DCW6Nb7vhgEaiDCW6Nb7vhgEaiDCW6Nb7vhgEai" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_HBAI_2147809005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.HBAI!MTB"
        threat_id = "2147809005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f4 33 45 f0 33 f0 3b f7 74 08 85 1d ?? ?? ?? ?? 75 05 be 4f e6 40 bb 89 35 ?? ?? ?? ?? f7 d6 89 35 ?? ?? ?? ?? 5e 5f 5b c9 c3}  //weight: 10, accuracy: Low
        $x_1_2 = "bkxtnds.exe" ascii //weight: 1
        $x_1_3 = "bkgrnd.exe" ascii //weight: 1
        $x_1_4 = "Zuhamohimo" ascii //weight: 1
        $x_1_5 = "Huwenond" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GSH_2147809631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GSH!MTB"
        threat_id = "2147809631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 06 8b 4d a4 81 f1 ?? ?? ?? ?? 03 f1 8b 16 c1 c2 ?? 83 e2 ?? 03 c2 4f 89 03 b9 02 00 00 00 c1 c9 ?? 03 d9 85 ff 75 ac e9 3b ff ff ff 8d 49 00}  //weight: 10, accuracy: Low
        $x_10_2 = {b9 d9 2d ce 63 81 f1 ?? ?? ?? ?? 03 cb 8b 11 03 d3 bf ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 03 fa 8b 37 03 f3 eb 88}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GFE_2147809827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GFE!MTB"
        threat_id = "2147809827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 5d 08 2b df 89 5d fc 80 3f 00 74 0f 8b 4d fc 47 0f b6 0c 39 0f b6 1f 2b cb 74 ec}  //weight: 10, accuracy: High
        $x_10_2 = {8b 47 04 6a 09 d1 e8 33 d2 59 f7 f1 85 d2 74 17}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DA_2147810301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DA!MTB"
        threat_id = "2147810301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 84 c1 cf 17 0f b6 17 47 47 c1 c7 17 89 7d 84 b9 bb ea 54 3f 81 c1 05 16 ab c0 3b d1 0f 82 ?? ?? ?? ?? 2b d1 03 d2 8b 45 fc c1 c8 13 03 c2 03 c2 c1 c8 0d 89 45 fc 85 d2 75 c4}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0e 8b 45 b4 35 11 2f dd f5 03 f0 8b 16 c1 c2 1f 83 e2 15 03 ca 4b 89 0f b8 88 68 18 ec 05 7c 97 e7 13 03 f8 85 db 0f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_CA_2147810510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.CA!MTB"
        threat_id = "2147810510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 83 c0 01 89 45 f4 8b 4d f4 3b 4d 10 7d 1f 8b 55 f4 89 55 fc 8b 45 0c 03 45 fc 0f b6 08 89 4d f0 8b 55 08 03 55 f4 8a 45 f0 88 02 eb d0}  //weight: 1, accuracy: High
        $x_1_2 = {23 d0 81 ea [0-4] 89 55}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GTS_2147810541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GTS!MTB"
        threat_id = "2147810541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 75 08 8b 7d fc 8b 4d 0c c1 e9 02 f3 a5 8b 55 fc 03 52 3c 89 95 68 ff ff ff 66 f7 42 16 00 20 74 0e}  //weight: 10, accuracy: High
        $x_10_2 = {51 8b 48 10 8b 70 14 8b 78 0c 03 75 fc 03 7d f8 f3 a4 59 83 c0 28 e2 e8}  //weight: 10, accuracy: High
        $x_1_3 = "Liperck" ascii //weight: 1
        $x_1_4 = "bronikc" ascii //weight: 1
        $x_1_5 = "edinalrdo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GFS_2147810543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GFS!MTB"
        threat_id = "2147810543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 0f 8a e9 32 c5 fe c1}  //weight: 10, accuracy: High
        $x_10_2 = {8b 45 fc 83 c0 20 03 f0 8b 3e 83 ee 0c 8b 06 03 7d fc 89 45 f4 83 ee 14 33 d2 8b 5d 0c c3 c3}  //weight: 10, accuracy: High
        $x_1_3 = "\\1.scr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_2147810549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.rrdh!MTB"
        threat_id = "2147810549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "rrdh: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 8b 06 8a e0 32 e1 8a c4}  //weight: 10, accuracy: High
        $x_10_2 = {01 c3 ff 08 33 33 c0 ff 10 40 ff 10 10 cc c3 10 75 40 03 40 e8 33 01 75 10}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GIL_2147810959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GIL!MTB"
        threat_id = "2147810959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 75 08 bb 0a 00 00 00 8b 4d 0c c1 e9 02 33 d2 8b 45 0c c1 e8 02 2b c1 50 f7 f3 83 c2 02 29 16 33 d2 58 f7 f3 03 14 24 81 c2 a0 82 f9 45 31 16 83 c6 04 e2 d9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GME_2147811341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GME!MTB"
        threat_id = "2147811341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 08 89 45 fc 8b 4d 10 8b 55 10 83 ea 01 89 55 10 85 c9 74 1e 8b 45 08 8b 4d 0c 8a 11 88 10 8b 45 08 83 c0 01 89 45 08 8b 4d 0c 83 c1 01 89 4d 0c eb d2 8b 45 fc 8b e5 5d c2 0c 00}  //weight: 10, accuracy: High
        $x_10_2 = {8b c8 c1 f9 05 8b 0c 8d 20 f2 43 00 83 e0 1f c1 e0 06 f6 44 08 04 01 74 cd 8b 04 08 5d c3}  //weight: 10, accuracy: High
        $x_1_3 = "nKERNEL32.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GMS_2147811344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GMS!MTB"
        threat_id = "2147811344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f4 0f b6 80 50 d0 d1 14 33 45 f4 8b 4d f4 88 81 50 d0 d1 14 eb 01}  //weight: 10, accuracy: High
        $x_1_2 = "GetProcAddress" ascii //weight: 1
        $x_1_3 = "LoadModule" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GWW_2147811654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GWW!MTB"
        threat_id = "2147811654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 17 8b 74 24 14 0f b6 c3 8a 04 30 8b 74 24 1c 02 c2 02 c8 88 4c 24 11 0f b6 c9 fe c3 8a 04 31 88 07 88 14 31 0f b6 c3 33 d2 66 3b 44 24 12 0f b6 cb 0f 44 ca 47 8a d9 8a 4c 24 11 4d 75 c1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_WQ_2147811655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.WQ!MTB"
        threat_id = "2147811655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 54 39 ff d0 c2 80 f2 7e 88 54 39 ff 49 83 f9 00 75 ed}  //weight: 10, accuracy: High
        $x_10_2 = {56 33 de 33 f3 33 de 5e 81 c3 ?? ?? ?? ?? 83 ec ?? c7 04 24 ?? ?? ?? ?? 54 68 32 01 00 00 83 ec ?? 89 3c 24 83 ec ?? 89 04 24 ff 13 8d 07 8b 40 ?? 03 c7 8b 40 29}  //weight: 10, accuracy: Low
        $x_1_3 = "JRhr.dlhduse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_Q_2147811675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.Q!MTB"
        threat_id = "2147811675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 85 4f fd ff ff 8b 8d 1c fc ff ff 81 e1 ff ff 00 00 0f b7 c9 81 e1 ff 00 00 00 0f b6 c9 33 c1 8b 8d 54 fd ff ff 88 84 0d 4c fc ff ff}  //weight: 10, accuracy: High
        $x_3_2 = "Ptscan.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_2147811987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.dwuq!MTB"
        threat_id = "2147811987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "dwuq: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f2 d1 ee 57 8b f9 74 2e 53 8d 1c 3e 2b d6 8b cb e8 ?? ?? ?? ?? 8b d6 8b cf e8 ?? ?? ?? ?? 33 c0 85 f6 74 11}  //weight: 10, accuracy: Low
        $x_10_2 = {8b f8 8b 45 f4 8b cf 2b c7 be ?? ?? ?? ?? 8a 14 08 88 11 41 4e 75 f7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GMP_2147811988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GMP!MTB"
        threat_id = "2147811988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nmsiexec.exe" ascii //weight: 1
        $x_1_2 = "%BOTID%" ascii //weight: 1
        $x_1_3 = "%BOTNET%" ascii //weight: 1
        $x_1_4 = "HTTP/1.1" ascii //weight: 1
        $x_1_5 = "Ol~OikozluWpawVuw" ascii //weight: 1
        $x_1_6 = "swyYwmurf|fl" ascii //weight: 1
        $x_1_7 = "__injectEntryForThreadEntry@4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GTK_2147811989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GTK!MTB"
        threat_id = "2147811989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "glower.exe" ascii //weight: 1
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "DllFunctionCall" ascii //weight: 1
        $x_1_4 = "ZPOWTWZHFDTPTQYBQBurghIO" ascii //weight: 1
        $x_1_5 = "QBurghIODAGDKZ" ascii //weight: 1
        $x_1_6 = "DKZPOWTW^HFDWPTQ" ascii //weight: 1
        $x_1_7 = "GDTPTQYBQBurghIODAGD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AAN_2147811990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AAN!MTB"
        threat_id = "2147811990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 08 03 55 f4 8b 02 03 45 f4 8b 4d 08 03 4d f4 89 01 c7 45 fc ?? ?? ?? ?? 8b 55 f4 83 c2 18 89 15 ?? ?? ?? ?? 8b 45 f8 89 45 f0 c7 45 fc 6a 01 00 00 8b 0d c0 21 44 00 89 4d ec 8b 55 08 03 55 f4 8b 02 33 45 ec 8b 4d 08 03 4d f4 89 01 eb 97}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 08 89 45 fc 8b 4d 0c 89 4d f8 8b 55 fc 3b 55 f8 73 07 8b 45 fc eb 05 eb 03 8b 45 f8 8b e5 5d c3}  //weight: 10, accuracy: High
        $x_1_3 = "WetPJocA4dreKs" ascii //weight: 1
        $x_1_4 = "Loaddibr9ryE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_UR_2147812158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.UR!MTB"
        threat_id = "2147812158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7c 24 04 31 c9 8a 2f 32 2a 88 2f fe c1 42 80 f9 ?? 75 05 31 c9 83 ea ?? 47 39 f8 75 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {56 57 33 ff 39 7c 24 0c 76 15 8b f1 2b f0 8a 0c 06 8a 10 3a ca 75 0f 47 40 3b 7c 24 0c 72 ef 33 c0 5f 5e c2 04 00 0f b6 d2 0f b6 c1 2b c2 eb f1}  //weight: 10, accuracy: High
        $x_1_3 = "CreateMutex" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_CI_2147812208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.CI!MTB"
        threat_id = "2147812208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spyware not founded on this system" wide //weight: 1
        $x_1_2 = "Removing spyware" wide //weight: 1
        $x_1_3 = "Can't find encryption_key entry" wide //weight: 1
        $x_1_4 = "Failed to remove spyware! Try again or restart computer" wide //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "Remove spyware from this system" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GWD_2147812601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GWD!MTB"
        threat_id = "2147812601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "107.65.79.65" ascii //weight: 1
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "gfuouqugysgidsmyt" ascii //weight: 1
        $x_1_4 = "qxjivevyvei" ascii //weight: 1
        $x_1_5 = "tifvwnkbiakmc" ascii //weight: 1
        $x_1_6 = "mbuetbqjhgjyi" ascii //weight: 1
        $x_1_7 = "oiurjfsiskdwmig" ascii //weight: 1
        $x_1_8 = "awucobtst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GB_2147812771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GB!MTB"
        threat_id = "2147812771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 13 8b 4d a0 c1 c9 13 03 d9 8b 03 c1 c0 0b 83 e0 05 03 d0 4f 89 16 b9 00 02 00 00 c1 c9 07 03 f1 85 ff 75 ac}  //weight: 10, accuracy: High
        $x_10_2 = {8b c6 c1 e0 10 0b f0 89 35 98 e0 40 00 f7 d6 89 35 9c e0 40 00 5e 5f 5b c9 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GQQ_2147812773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GQQ!MTB"
        threat_id = "2147812773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 7d fc 7d 0b 83 ce ff d3 ee 83 4d f8 ff eb 0d 83 c1 e0 83 c8 ff 33 f6 d3 e8 89 45 f8 a1 a0 95 40 00 8b d8 89 75 f4 3b df eb 14 8b 4b 04 8b 3b 23 4d f8 23 fe 0b cf 75 0b 83 c3 14 3b 5d fc 89 5d 08 72 e7}  //weight: 10, accuracy: High
        $x_1_2 = "Ytozmuqda" ascii //weight: 1
        $x_1_3 = "Hawuqyiqo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GDT_2147812774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GDT!MTB"
        threat_id = "2147812774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 45 00 32 c3 89 75 18 24 03 30 45 00 83 fb 01}  //weight: 10, accuracy: High
        $x_1_2 = "aulbbiwslxpvvphxnjij.biz" ascii //weight: 1
        $x_1_3 = "micrsolv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GTT_2147812776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GTT!MTB"
        threat_id = "2147812776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ec 8b 4d 10 33 d2 8b 75 04 8b 36 03 f3 33 c0 50 c1 c8 07 31 04 24 ac 84 c0 75 f5}  //weight: 10, accuracy: High
        $x_10_2 = {d1 e2 8b 4d 00 03 cb 03 ca 8b 09 81 e1 ?? ?? ?? ?? 8b 55 0c 03 d3 c1 e1 02 03 d1 8b 12 03 d3 89 17 8b 4d 08 03 cb 89 4d 04 5f eb 9d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_CB_2147812940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.CB!MTB"
        threat_id = "2147812940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 07 03 fb 03 02 89 02 03 d3 49 75 f3}  //weight: 2, accuracy: High
        $x_1_2 = "C:\\Users\\admin\\Downloads\\hromi.exe" wide //weight: 1
        $x_1_3 = "C:\\Users\\maxine\\AppData\\Local\\Temp\\file.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GNM_2147812987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GNM!MTB"
        threat_id = "2147812987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 5d d0 c1 c3 1c ba c8 41 b6 13 81 c2 ?? ?? ?? ?? 23 da b9 65 73 4f 8c 81 f1 ?? ?? ?? ?? b8 00 00 ff ff c1 c0 10 eb ?? 0b da 8b ff 8b e5 5d c2 10 00}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 13 2b d8 23 d0 4b 3b d1 75 f5 e9 54 02 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_ZR_2147812988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.ZR!MTB"
        threat_id = "2147812988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d d8 8b 55 e0 23 fa 89 7d e0 8b 45 c8 8b 55 e0 33 c2 89 45 e0 8b 35 00 00 43 00 f7 d6 46 89 35 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b c2 89 15 93 37 43 00 e9 80 00 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 3d cf 87 44 00 f7 df 81 c7 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 83 c2 68 f7 d2 89 15 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 23 d3 89 1d ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 33 c1 89 0d ef 87 44 00 8b 35 97 37 43 00 81 f6 e1 0a 38 85 89 35 3c 00 43 00 c9 c2 10 00}  //weight: 10, accuracy: Low
        $x_1_3 = "Bride.exe" ascii //weight: 1
        $x_1_4 = "LoadResource" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_ABA_2147812990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.ABA!MTB"
        threat_id = "2147812990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 75 fc 83 ee f1 f7 c6 66 9f 00 00 75 16 33 f3 ba 57 00 00 00 89 b5 44 ff ff ff 89 7d 90 89 95 58 ff ff ff 89 45 cc 5f 8b f7 89 b5 68 ff ff ff 5e f7 c6 87 00 00 00 75 15 33 c7 8b 8d 5c ff ff ff 89 4d e0 3b c7 75 06}  //weight: 10, accuracy: High
        $x_1_2 = "comsvcs.dll" ascii //weight: 1
        $x_1_3 = "GetVolumeInformation" ascii //weight: 1
        $x_1_4 = "QueryDosDevice" ascii //weight: 1
        $x_1_5 = "LoadResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GTR_2147813281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GTR!MTB"
        threat_id = "2147813281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 44 8b 00 8b 55 40 8a 14 0a 88 14 08 8b 45 10 8b 55 14 33 c6 8d 8c 01 ?? ?? ?? ?? 8b 45 1c 8b 00 3b 48 54 72 d9 8b 45 1c 8b 08 0f b7 49 14 8b 10 8d 4c 0a 18 89 4d 24 8b 4d 08 8b 55 0c 33 ce 2b cf eb 62}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 e8 8b 55 e4 69 c0 ?? ?? ?? ?? 8b 5d ?? 2b c2 33 d2 f7 f3 8b d1 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? 33 c6 2b d0 3b d7 0f 86}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_CN_2147813742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.CN!MTB"
        threat_id = "2147813742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d9 41 f7 e1 89 85 [0-4] 33 85 [0-4] 8b 95 [0-4] 89 02 83 c6 08 83 45 f8 08 83 c6 fc 83 45 f8 fc 83 3e 00 75 94}  //weight: 1, accuracy: Low
        $x_1_2 = {89 f9 89 da d3 fa 29 d7 8b 55 e8 29 fa 89 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_CJ_2147813928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.CJ!MTB"
        threat_id = "2147813928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 d9 41 f7 e1 89 85 50 ff ff ff 33 85 58 ff ff ff 8b 95 54 ff ff ff 89 02}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f8 8d 1c 03 31 f0 01 45 fc 09 f6 74 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_EC_2147814124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.EC!MTB"
        threat_id = "2147814124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 08 8d 0c 06 8a c3 02 45 fc 32 01 32 45 f8 32 c3 88 01 85 db 75 04 34 02 88 01}  //weight: 10, accuracy: High
        $x_3_2 = "tmp\\where.pdb" ascii //weight: 3
        $x_3_3 = "InternetOpenUrlA" ascii //weight: 3
        $x_3_4 = "InternetReadFile" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zbot_BK_2147815647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BK!MTB"
        threat_id = "2147815647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 f7 d2 f7 d9 33 ce 03 d6 0f ba e1 08 72 01}  //weight: 1, accuracy: High
        $x_1_2 = {33 d5 4a 21 cb f7 d1 4b 2b ca 32 c4 03 ca 85 fe 74 05}  //weight: 1, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "gethostname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_CD_2147815648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.CD!MTB"
        threat_id = "2147815648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 85 20 fe ff ff 28 01 00 00 c6 85 10 fe ff ff 61 c6 85 11 fe ff ff 76 c6 85 12 fe ff ff 61 c6 85 13 fe ff ff 73 c6 85 14 fe ff ff 74 c6 85 15 fe ff ff 73 c6 85 16 fe ff ff 76 c6 85 17 fe ff ff 63 c6 85 18 fe ff ff 2e c6 85 19 fe ff ff 65 c6 85 1a fe ff ff 78 c6 85 1b fe ff ff 65 c6 85 1c fe ff ff 00 8d 85}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_CK_2147818365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.CK!MTB"
        threat_id = "2147818365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spyware not founded on this system" wide //weight: 1
        $x_1_2 = "Removing spyware" wide //weight: 1
        $x_1_3 = "Can't find encryption_key entry" wide //weight: 1
        $x_1_4 = "Failed to remove spyware! Try again or restart computer" wide //weight: 1
        $x_1_5 = "Building bot file" wide //weight: 1
        $x_1_6 = "Remove spyware from this system" wide //weight: 1
        $x_1_7 = "botnet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_CM_2147818489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.CM!MTB"
        threat_id = "2147818489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 1e 0f b6 c8 32 d8 83 e1 07 d2 cb 88 1e 8b 5c 24 18 80 c2 01 83 c6 01 83 ef 01 75 b3}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_WM_2147818579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.WM!MTB"
        threat_id = "2147818579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {92 52 d0 14 c7 05 ?? ?? ?? ?? 78 11 d0 14 66 89 35 c8 16 d1 14 c7 05 ?? ?? ?? ?? bd 52 d0 14 c7 05 ?? ?? ?? ?? 64 11 d0 14 66 89 35 d8 16 d1 14 c7 05 ?? ?? ?? ?? f7 52 d0 14 c7 05 ?? ?? ?? ?? 50 11 d0 14}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 7c 8b 40 04 8b 55 64 8a 04 38 8b 4d 50 ff 45 64 88 04 11 8b 45 7c 8b 48 08 47 ff 45 58 ff 45 5c 3b f9 89 7d 60 0f 82 d7 fe ff ff}  //weight: 10, accuracy: High
        $x_1_3 = "195.189.246.235" ascii //weight: 1
        $x_1_4 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BD_2147819222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BD!MTB"
        threat_id = "2147819222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 06 0f b6 ca 83 e1 ?? 32 c2 d2 c8 88 06 fe c3 46 4f 75 c2}  //weight: 2, accuracy: Low
        $x_2_2 = "VirtualAlloc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPM_2147819257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPM!MTB"
        threat_id = "2147819257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c0 e0 06 0a c2 8d 93 ?? ?? ?? ?? 81 ca ?? ?? ?? ?? 88 84 3a ?? ?? ?? ?? b8 ?? ?? ?? ?? 33 d2 f7 f6 33 d2 bf ?? ?? ?? ?? f7 f7 8a 45 ?? 8b fa 81 f7 ?? ?? ?? ?? 3c e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BE_2147819314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BE!MTB"
        threat_id = "2147819314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2a c1 f6 6d fc 8a d8 8a c1 f6 ea 2a d8 02 1d [0-4] 02 1d [0-4] 80 eb 02 30 1c 31 39 3d [0-4] 7e 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BG_2147820501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BG!MTB"
        threat_id = "2147820501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 c4 8b 4d cc 8a 10 32 11 8b 45 c4 88 10 68 [0-4] e8 [0-4] 83 c4 04 8b f0 68 [0-4] e8 [0-4] 83 c4 04 3b f0 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BH_2147823836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BH!MTB"
        threat_id = "2147823836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f0 89 35 [0-4] 8b 55 d8 8b 45 e8 33 c2 89 45 d8 8b 5d fc 8b 45 d8 2b d8 89 5d d8 3b f0 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {23 c7 89 05 [0-4] 8b 1d [0-4] 33 df 89 1d [0-4] 8b 3d [0-4] 47 4f 89 3d [0-4] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_A_2147823975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.A!MTB"
        threat_id = "2147823975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 c1 da 05 33 dd 33 ff bf 2a 23 39 8c ff 75 bc c1 ca 0a b9 fe 4e f7 e0 c1 de 03 ff 15 6c d1 40 00 83 c4 04 c1 c2 01 89 d9 bb b6 54 1e 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_A_2147823975_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.A!MTB"
        threat_id = "2147823975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CarWorker.ex" ascii //weight: 1
        $x_1_2 = "hgkytiygkhvmnbvfjhgfuyeredgfdhgkjhgkhgjgfhdyretrfdcbvcnvcn" wide //weight: 1
        $x_1_3 = "RoadSiderMount" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BI_2147824023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BI!MTB"
        threat_id = "2147824023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ce 2b c1 03 c7 81 1d [0-4] ef b4 45 00 33 c6 81 05 [0-4] 3e 78 00 00 89 45 ?? 8b 45 ?? 33 c6 2b c7 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c6 2b c7 89 01 8b 45 ?? 8b 4d ?? 33 c6 2b c7 3b c8 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BJ_2147824250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BJ!MTB"
        threat_id = "2147824250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c6 03 c7 89 45 ec 8b 45 ec 2b c7 33 c6 89 45 ec 8b 45 ec 8b 4d e8 3b c8 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {33 c8 33 d0 2b ca 2b ce 33 c8 89 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_C_2147824385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.C!MTB"
        threat_id = "2147824385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b fb f3 a5 2d dc 07 00 00 04 3c 33 c9 66 a5 d0 e0 30 04 19 41 83 f9 7a 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_C_2147824385_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.C!MTB"
        threat_id = "2147824385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f1 8b 0d ?? ?? ?? ?? 83 c1 52 8b 85 38 fc ff ff 33 d2 f7 f1 0f af 05 ?? ?? ?? ?? 2b f0 89 b5 48 fc ff ff 0f b6 95 0f fc ff ff 33 95 08 fc ff ff 88 95 07 fc ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BN_2147824852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BN!MTB"
        threat_id = "2147824852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 c0 02 bb b3 31 41 00 fe 03 43 81 fb c1 33 41 00 75 f5 b8 0b 00 00 00 47 81 ff 69 9c 01 00 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPZ_2147828541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPZ!MTB"
        threat_id = "2147828541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 d2 74 01 ?? 31 1f 81 c7 04 00 00 00 81 c1 ?? ?? ?? ?? 21 f6 39 d7 75 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPZ_2147828541_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPZ!MTB"
        threat_id = "2147828541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c2 89 c1 89 f8 83 ca 01 89 55 e8 99 f7 7d e8 01 c1 8b 45 cc 03 4d 08 09 f8 03 45 08 ff 4d e4 8a 10 88 55 e8 8a 11 88 10 8a 45 e8 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPZ_2147828541_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPZ!MTB"
        threat_id = "2147828541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 dd 08 c6 45 de 2b c6 45 df 08 c6 45 e0 5c c6 45 e1 08 c6 45 e2 31 c6 45 e3 08 c6 45 e4 5c c6 45 e5 08 c6 45 e6 52 c6 45 e7 08 c6 45 e8 31 c6 45 e9 08 c6 45 ea 3f c6 45 eb 08 c6 45 ec 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPF_2147829240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPF!MTB"
        threat_id = "2147829240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 55 db 8b 45 e8 8b 55 08 0f b6 4d e3 01 f1 88 0c 02 8b 45 ec 0f b6 4d db 31 f1 88 0c 02 ff 45 f0 81 7d f0 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BO_2147829276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BO!MTB"
        threat_id = "2147829276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 f7 33 c0 50 c1 c8 07 31 04 24 ac 84 c0 75}  //weight: 2, accuracy: High
        $x_2_2 = {03 d7 c1 e1 02 03 d1 8b 12 03 d7 89 13 8b 4d 08 03 cf 89 4d 04 5b e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BP_2147829292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BP!MTB"
        threat_id = "2147829292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GStub.exe" ascii //weight: 1
        $x_1_2 = "Exc\\Desktop\\Stub.exe" ascii //weight: 1
        $x_1_3 = "Del %temp%\\Melt.bat /F /Q" wide //weight: 1
        $x_1_4 = "AppData\\Local\\Temp\\RarSFX0" ascii //weight: 1
        $x_1_5 = "not initialized!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPT_2147829933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPT!MTB"
        threat_id = "2147829933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 ea 18 88 14 3e 8b c3 c1 e8 10 88 44 3e 01 8b 44 24 14 8b cb c1 e9 08 88 4c 3e 02 40 88 5c 3e 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RA_2147829997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RA!MTB"
        threat_id = "2147829997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d9 2b df 2b d8 8b 44 24 14 8b 00 81 eb 87 28 00 00 8b fb 8b 5c 24 1c 03 d9 8d 9c 2b ?? ?? ?? ?? 89 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RA_2147829997_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RA!MTB"
        threat_id = "2147829997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 7d fc 33 fe 03 c6 2b c6 56 59 46 87 c3 89 45 f4}  //weight: 1, accuracy: High
        $x_1_2 = {47 6a 00 6a 00 6a 00 6a 00 6a 79 6a 4b 6a 76 6a 18 68 00 00 80 00 6a 00 c7 05 ?? ?? ?? ?? 4c 49 53 54 c7 05 ?? ?? ?? ?? 42 4f 58 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BS_2147830321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BS!MTB"
        threat_id = "2147830321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {67 34 31 30 38 ce bb [0-4] 3e f7 97 a1 e3 e4 80 7a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BT_2147830838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BT!MTB"
        threat_id = "2147830838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zkrvvcnmaebNbcZ" ascii //weight: 1
        $x_1_2 = "Application Data\\wsnpoem\\video.dll" wide //weight: 1
        $x_1_3 = "fk{vtelpp]hg[_\\HXMZ[QRI" ascii //weight: 1
        $x_1_4 = "zkrvvcnmaebNUf\\VWXIT" ascii //weight: 1
        $x_1_5 = "fk{vtelpp]hg[_\\HaQTPQGMJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_R_2147831320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.R!MTB"
        threat_id = "2147831320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Application Data\\wsnpoem\\video.dll" wide //weight: 1
        $x_1_2 = "zkrvvcnmaebNbcZ" ascii //weight: 1
        $x_1_3 = "fk{vtelpp]hg[_\\HXMZ[QRI" ascii //weight: 1
        $x_1_4 = "zkrvvcnmaebNUf\\VWXIT" ascii //weight: 1
        $x_1_5 = "fk{vtelpp]hg[_\\HaQTPQGMJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_R_2147831320_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.R!MTB"
        threat_id = "2147831320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WINDOWS\\system32\\wsnpoem\\video.dll" wide //weight: 1
        $x_1_2 = "WINDOWS\\system32\\ntos.exe" wide //weight: 1
        $x_1_3 = "zkrvvcnmaebNbcZ" ascii //weight: 1
        $x_1_4 = "fk{vtelpp]hg[_\\HXMZ[QRI" ascii //weight: 1
        $x_1_5 = "zkrvvcnmaebNUf\\VWXIT" ascii //weight: 1
        $x_1_6 = "fk{vtelpp]hg[_\\HaQTPQGMJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_R_2147831320_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.R!MTB"
        threat_id = "2147831320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CompanyNameeckYIkYUI8" wide //weight: 1
        $x_1_2 = "OriginalFilenamexdhf9JTv7" wide //weight: 1
        $x_1_3 = "WINDOWS\\system32\\ntos.exe" wide //weight: 1
        $x_1_4 = "9jbrNNxZ" wide //weight: 1
        $x_1_5 = "eWmWO8CQe" wide //weight: 1
        $x_1_6 = "l3Ddxtt5fT" wide //weight: 1
        $x_1_7 = "zkrvvcnmaebNbcZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BV_2147831531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BV!MTB"
        threat_id = "2147831531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 8a 88 [0-4] 30 8c 05 f8 fe ff ff 40 56 89 45 fc e8 [0-4] 59 39 45 fc 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BX_2147831642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BX!MTB"
        threat_id = "2147831642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {cc 6d 40 00 4c 00 00 00 50 00 00 00 32 6e 58 a2 82 5d f1 41 98 77}  //weight: 5, accuracy: High
        $x_5_2 = {33 a1 44 89 ba 49 d6 87 08 87 e5 32 6e 58 a2 82 5d f1 41 98 77}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPN_2147831920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPN!MTB"
        threat_id = "2147831920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 32 50 57 53 5f 56 58 ab 5f 58 83 2b 01 f7 d9 f8 19 0b ff 32 8d 52 04 8d 5b 04 59 f3 0f c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPN_2147831920_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPN!MTB"
        threat_id = "2147831920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 14 03 0f b6 55 db 89 55 bc 8b 7d e4 89 f0 89 45 c0 89 d1 80 c9 01 31 d2 f7 f1 89 45 b8 8b 55 bc 89 c1 01 d1 89 ca 88 14 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BY_2147832517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BY!MTB"
        threat_id = "2147832517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 16 00 da f6 d0 88 d0 f6 d0 aa 83 c6 04 83 c7 03 ba 30 00 00 00 83 e9 04 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPG_2147832528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPG!MTB"
        threat_id = "2147832528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 00 88 45 fc 8a 22 80 cc 01 88 d8 f6 e4 8a 3a 28 c7 8a 45 fc 88 39 08 d8 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPX_2147833388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPX!MTB"
        threat_id = "2147833388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 8b 0d 30 00 00 00 f8 81 e8 00 00 00 00 f8 f5 8d 00 3c 8f c0 c8 28 60 60 60}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPX_2147833388_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPX!MTB"
        threat_id = "2147833388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c6 33 d2 b9 b0 03 00 00 f7 f1 8a 55 ff 8b c8 8a 45 fe 80 c1 02 d2 ea 8d 8e d2 fd ff ff d2 e0 8b 4d f4 0a d0 8b c7 69 c0 8f 00 00 00 23 c6 25 bb 01 00 00 88 54 08 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AH_2147833534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AH!MTB"
        threat_id = "2147833534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "c:\\windows\\SearchApp.exe" wide //weight: 2
        $x_2_2 = "qwer23.com/DOWN/A1.exe" wide //weight: 2
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AI_2147833535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AI!MTB"
        threat_id = "2147833535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0a 32 c2 88 45 f3 8d 45 fc e8 [0-4] 8b 55 fc 8a 54 1a ff 80 e2 f0 80 e2 f0 8a 4d f3 02 d1 88 54 18 ff 46 8b 45 f8 e8 [0-4] 3b f0 7e ?? be 01 00 00 00 43 4f 75}  //weight: 2, accuracy: Low
        $x_2_2 = {88 14 18 33 db 8a 98 00 01 00 00 02 14 18 81 e2 ff 00 00 00 8a 14 10 32 16 88 11 41 46 ff 4d fc 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BQ_2147835175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BQ!MTB"
        threat_id = "2147835175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {fe 00 40 3d 87 32 41 00 75 f6 43 81 fb ad 8b 01 00 75}  //weight: 5, accuracy: High
        $x_1_2 = "onsbwd" ascii //weight: 1
        $x_1_3 = "wboxsh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AJ_2147835176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AJ!MTB"
        threat_id = "2147835176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {47 73 40 00 46 00 01 01 63 73 40 00 43 00 01 01 83 73 40 00 44 00 01 01 9f}  //weight: 3, accuracy: High
        $x_2_2 = "tgtqf" ascii //weight: 2
        $x_2_3 = "ixsd" ascii //weight: 2
        $x_2_4 = "mxsvwp" ascii //weight: 2
        $x_2_5 = "ilobqt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zbot_AK_2147835177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AK!MTB"
        threat_id = "2147835177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {fe 03 43 33 d2 81 fb e1 32 41 00 75 f3 40 b9 00 00 00 00 33 c8 33 c9 3d e5 99 01 00 75}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RE_2147835670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RE!MTB"
        threat_id = "2147835670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a 40 00 64 2a 40 00 58 2a 40 00 4c 2a 40 00 40 2a 40 00 34 2a 40 00 20 2a 40 00 14 2a 40 00 0c 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RE_2147835670_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RE!MTB"
        threat_id = "2147835670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be c9 89 cb 09 fb 31 c3 89 de c1 e6 0a 89 f7}  //weight: 1, accuracy: High
        $x_1_2 = "pikmkgcyvtfkyheiqghg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BR_2147836301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BR!MTB"
        threat_id = "2147836301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 f7 29 35 [0-4] 03 d0 e8 [0-4] 2b f7 8b 45 ec 46 8b c1 4f 81 f9 c6 1c 42 4a 0f 85}  //weight: 5, accuracy: Low
        $x_5_2 = {33 d8 89 5d f8 03 7d fc 33 df 48 74}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AN_2147836837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AN!MTB"
        threat_id = "2147836837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0c 13 32 c8 40 88 0a 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 42 83 ee 01 75}  //weight: 2, accuracy: High
        $x_2_2 = "Ihq_{JTQWtWOQAEOLI" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AP_2147836841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AP!MTB"
        threat_id = "2147836841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 88 13 01 00 05 b1 96 07 00 2d 2a 93 07 00 89 d1 51 6a 40 68 00 30 00 00 50 83 ec 04 c7 04 24 00 00 00 00 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = {88 d7 02 3e 81 c6 72 c4 0c 00 81 ee 71 c4 0c 00 88 3f 00 1f 83 c7 01 83 ec 04 89 14 24}  //weight: 1, accuracy: High
        $x_1_3 = {8b 14 24 83 c4 04 2d 71 e7 0c 00 05 75 e7 0c 00 c1 ea 08 81 ed df c3 05 00 81 c5 e0 c3 05 00 39 c5 75 0c bd d2 71 bf 7f 89 ea bd 00 00 00 00 81 c1 3d f5 09 00 81 e9 3e f5 09 00 83 f9 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AS_2147837792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AS!MTB"
        threat_id = "2147837792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b d8 bf eb 00 00 00 31 3a 8d 1c 10 02 db 8b d9 8b cb 8b 32 1b d8 21 fb 81 c6 04 00 00 00 89 32 76}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AT_2147837890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AT!MTB"
        threat_id = "2147837890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {21 c1 29 f7 58 bb 07 00 00 00 83 eb 04 ba f3 21 40 00 f7 d3 f7 db 81 ff 52 64 00 00 fe 02 83 c2 fe 90 83 c2 03 81 fa 87 53 41 00 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RJ_2147837973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RJ!MTB"
        threat_id = "2147837973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 cf 87 da 01 75 c0 03 4d a0 4a 89 75 b8 2b ce 99 33 d6 03 ce 03 d2 87 ca 2b d9 03 4d c0 89 6d f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RJ_2147837973_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RJ!MTB"
        threat_id = "2147837973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XMbXb2ZNdhc9mnosAWIjW4WCJV0AsOqmiVRBRjcJuC2aFvw0RuUnKmsj1lfz" ascii //weight: 1
        $x_1_2 = "BPI8uvix5ady2errXx2e3UsJMnyg76iOP4qnLKkdjfhJxniFe7cn1U0CfYtlc1kvEo" ascii //weight: 1
        $x_1_3 = "H67qWpwIXUHtyBJc6l8qPnt2h02sQyjscmzkgOU2Z84DRLAWUa3r9k6Q4Wa0DG" ascii //weight: 1
        $x_1_4 = "Hs0hDD5NWhForUTqjo7M94d9vZkWvmv0PEpiKyEGL1h8Qg7pomY2KeFa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AU_2147838101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AU!MTB"
        threat_id = "2147838101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 45 fc 03 7d ec 54 58 89 65 fc 89 7d f0 89 5d f0 33 fe 03 45 f4 89 5d ec 33 fe 01 5d ec 89 65 f4 8b 75 f4 46 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AV_2147838229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AV!MTB"
        threat_id = "2147838229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b7 55 b0 0f b7 45 a4 0f af d0 8b 45 b8 0f b6 0c 10 83 f1 44 8b 45 b4 01 c8 89 45 b4 0f b7 55 a4 c1 e2 18 88 55 a0 8a 55 ac 84 d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AW_2147838248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AW!MTB"
        threat_id = "2147838248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {29 d1 8b 55 c4 0f b6 04 0a 83 f0 5e 8b 4d bc 01 c1 89 4d bc 0f b6 4d b0 89 4d ac 8b 4d c4 83 c1 01 89 4d c4 8b 55 08 88 55 a8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AX_2147838370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AX!MTB"
        threat_id = "2147838370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Temp\\jZip\\jZip232DE\\jZipC3D8\\Xerox_Scan_002_20112013.exe" wide //weight: 1
        $x_1_2 = "C:\\G7yDWg4m.exe" wide //weight: 1
        $x_1_3 = "C:\\hRTi3VNE.exe" wide //weight: 1
        $x_1_4 = "C:\\TnHNHnZx.exe" wide //weight: 1
        $x_1_5 = "C:\\WaFObEk9.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAB_2147839916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAB!MTB"
        threat_id = "2147839916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {32 c2 08 07 8b 45 ?? 0f b6 10 23 15 ?? ?? ?? ?? 8b c3 2b c2}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAB_2147839916_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAB!MTB"
        threat_id = "2147839916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ff 30 5f d3 cf 68 7d 26 80 60 5a 03 54 24 0c 31 d7 89 3e 81 e1 00 00 00 00 f7 df 29 f9 f7 df c1 e9 03 85 ed 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAB_2147839916_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAB!MTB"
        threat_id = "2147839916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppData\\Local\\Temp\\Temp1_VoiceMessage.zip\\VoiceMessage.exe" wide //weight: 1
        $x_1_2 = "C:\\fByPDk1s.exe" wide //weight: 1
        $x_1_3 = "C:\\BWHrtJUQ.exe" wide //weight: 1
        $x_1_4 = "C:\\GeWpL7uT.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAA_2147840125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAA!MTB"
        threat_id = "2147840125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8a 94 06 32 09 00 00 88 14 08 8b 7c 24 10 40 3b c7 72}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAA_2147840125_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAA!MTB"
        threat_id = "2147840125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 33 f8 83 d3 ?? f7 d6 83 c6 ?? 01 d6 83 ee ?? 29 d2 31 f2 89 31}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAA_2147840125_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAA!MTB"
        threat_id = "2147840125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 8b 8d 68 dc ff ff 51 6a 00 ff 15 [0-4] 89 85 1c dc ff ff 6a 00 8d 95 40 dc ff ff 52 6a 0e 8d 85 44 dc ff ff 50 8b 8d 20 dc ff ff 51 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RF_2147840249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RF!MTB"
        threat_id = "2147840249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 40 00 01 01 ec 71 40 00 41 00 01 01 08 72 40 00 63 00 00 00 28 72 40 00 64 00 00 00 28 72 40 00 62 00 01 01 54 72 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPQ_2147840363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPQ!MTB"
        threat_id = "2147840363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 00 c2 00 00 b0 7d b4 c5 30 06 46 28 26 46 fe c0 fe c4 83 e9 02 75 f1 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPQ_2147840363_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPQ!MTB"
        threat_id = "2147840363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 ff 8b ce 23 4d e8 8a 55 fe 81 e1 ?? ?? 00 00 83 e9 10 d2 e0 8a 4d 0c 80 e9 14 d2 ea 8b 4d 08 81 e1 ?? ?? 00 00 0a c2 8b 55 f0 81 f1 ?? ?? 00 00 88 84 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AZ_2147840783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AZ!MTB"
        threat_id = "2147840783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 4c 47 47 50 71 54 44 44 00 00 00 43 41 74 55 56 6e 65 4a 44 00 00 00 73 55 53 4a 77 69 00 00 6f 66 77 46 7a 58 00 00 73 6c 73 6a 7a 47 4f 4b}  //weight: 2, accuracy: High
        $x_2_2 = {6d 4a 44 78 64 59 70 43 59 00 00 00 68 77 4c 4b 79 66 00 00 55 56 63 6f 4f 67 61 58 00 00 00 00 74 5a 4a 53 45 4b 56 77 46 00 00 00 46 69 66 44 64 70 50 73 62 00 00 00 67 68 4f 4c 48 72}  //weight: 2, accuracy: High
        $x_1_3 = "DJdRkZILU" ascii //weight: 1
        $x_1_4 = "OvdTbVECV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPL_2147840846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPL!MTB"
        threat_id = "2147840846"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 04 52 56 56 83 2c 24 01 01 14 24 5e 8a 1e 5a 8b f2 5a 83 e9 01 80 f3 f1 c0 c3 06 80 eb 05 8a c2 fe c8 24 01 32 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAC_2147842541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAC!MTB"
        threat_id = "2147842541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {03 4d f0 8b 11 33 55 ec 8b 45 08 03 45 f0 89 10 e9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAC_2147842541_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAC!MTB"
        threat_id = "2147842541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 4f bf 50 34 68 54 31 06 5b 0a 0e 8b a6 f4 7e a1 cb 5f 6d ec b0 75 ac 44 53 98 8d 9b 56 24 fc 3d 4a c1 bc 7d b2 f8 b3 68 b6 b4 aa 15 19 89 f9 f8 53 a0 c7 4a 72 ea 59 5c 75}  //weight: 2, accuracy: High
        $x_2_2 = {a9 72 14 9e 09 3c 4a f9 a3 00 ca 74 40 23 60 8f 82 37 c9 3b 1f 6e 1b 48 0f 66 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RD_2147842984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RD!MTB"
        threat_id = "2147842984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 10 8a ca 80 e9 61 88 55 ff 80 f9 19 77 04 80 45 ff e0 8a 0c 06 8d 59 9f 80 fb 19 77 03 80 c1 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RG_2147842985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RG!MTB"
        threat_id = "2147842985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 b4 25 2c ff ff ff 8c 12 00 00 89 b4 25 ?? ff ff ff 8b 32 89 34 87 c1 2d ?? ?? ?? ?? 07 40 3b 45 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RG_2147842985_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RG!MTB"
        threat_id = "2147842985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 c1 ea 03 8b c8 83 c0 08 83 e1 07 89 35 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 14 2a d3 ea 8b ce 23 d3 8b ea d3 e5 8d 0c 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RG_2147842985_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RG!MTB"
        threat_id = "2147842985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 00 40 00 ff d6 6a 40 68 00 30 00 00 ff b5 70 ff ff ff 6a 00 ff 55 d4 8b d0 33 c0 eb 1f [0-32] 8a 0c 0b 8b b5 74 ff ff ff 32 0c 06 88 0c 02 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RH_2147842986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RH!MTB"
        threat_id = "2147842986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 8b 08 03 4d 10 8b 55 08 03 55 fc 66 89 0a 8b 45 f8 c1 e8 04 89 45 f8 8b 4d f8 83 e9 01 89 4d f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RH_2147842986_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RH!MTB"
        threat_id = "2147842986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AC:\\Max\\YLIQc\\Myevj.vbp" wide //weight: 1
        $x_1_2 = {45 3e d6 ba 63 25 5c 9c 2d 24 20 15 6f a3 9e b3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GHC_2147843714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GHC!MTB"
        threat_id = "2147843714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 c1 0f b6 04 0a 8b 0d ?? ?? ?? ?? 88 01 0f b6 45 e4 33 45 0c 0f b6 4d e0 31 c8 88 45 d8 0f b6 4d e4 a1 ?? ?? ?? ?? 0f b6 55 d8 33 d1 83 c2 e9 03 c2 a3 ?? ?? ?? ?? 0f b6 4d d8 8b 45 dc 29 c8 8b 4d f8 05 58 ff ff ff 01 c1 89 4d f8 0f b6 45 d8 89 45 d4 0f b6 45 e0 8b 0d ?? ?? ?? ?? 33 45 d4 2d ?? ?? ?? ?? 2b c8}  //weight: 10, accuracy: Low
        $x_1_2 = ".ropf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_CAZY_2147843858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.CAZY!MTB"
        threat_id = "2147843858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 f7 f1 66 89 55 e8 8b 4d 08 33 4d e4 81 c1 ?? ?? ?? ?? 89 4d e4 0f b7 4d e8 23 4d e4 8b 55 f4 0f b6 04 0a 0f b6 4d ec 31 c8 88 45 e0 0f b7 4d e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAD_2147843924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAD!MTB"
        threat_id = "2147843924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 4d f8 8b 55 14 8b 45 0c 03 02 8b 4d f8 8b 94 08 ?? ?? ?? ?? 03 55 10 8b 45 14 8b 4d 0c 03 08 8b 45 f8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAD_2147843924_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAD!MTB"
        threat_id = "2147843924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 44 24 10 8d 4c 24 20 50 51 6a 00 6a 00 6a 0c 6a 00 6a 00 8d 94 24 84 01 00 00 6a 00 52 6a 00 ff 15 40 20 40 00 85 c0 74 28 8b 44 24 10 6a 40}  //weight: 2, accuracy: High
        $x_2_2 = {15 b4 20 40 00 56 ff 15 b8 20 40 00 57 ff 15 bc 20 40 00 8b b4 24 48 02 00 00 8d 54 24 30 56 52 ff 15 c0 20 40 00 6a 06 56 ff 15 c4 20 40 00 8d 44 24 30 50 ff 15 c8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RN_2147843968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RN!MTB"
        threat_id = "2147843968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 f8 c8 db 00 00 8b 05 ?? ?? ?? ?? 89 45 dc 8b ?? dc 89 ?? e0 8b ?? e0 89 ?? e4 8b ?? e4 89 ?? e8 8b ?? 08 8b 55 08 03 55 f0 8b ?? 33 ?? e8 03 ?? f0 89 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RO_2147843969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RO!MTB"
        threat_id = "2147843969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 03 8d ?? ?? ff ff 8b 55 0c 03 95 ?? ?? ff ff 8a 02 88 01 83 bd ?? ?? ff ff 00}  //weight: 1, accuracy: Low
        $x_1_2 = "24gOp333eyA" ascii //weight: 1
        $x_1_3 = "vltMFmulTAanMeeW1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SP_2147844277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SP!MTB"
        threat_id = "2147844277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Global\\sendCmd%d" ascii //weight: 1
        $x_1_2 = "Cookie: BAIDUID=4551B3A873310A1D9F1D8F3847FADA52:FG=" ascii //weight: 1
        $x_1_3 = "Hm_lvt_9f14aaa038bbba8b12ec2a4a3e51d254=1381926448" ascii //weight: 1
        $x_1_4 = "Global\\recvCmd_%d" ascii //weight: 1
        $x_1_5 = "hi.baidu.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAF_2147844313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAF!MTB"
        threat_id = "2147844313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 02 83 c2 04 f7 d8 8d 40 d7 83 e8 02 83 c0 01 29 d8 89 c3 6a 00 8f 07 01 47}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAF_2147844313_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAF!MTB"
        threat_id = "2147844313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 8d ac fd ff ff 0f be 91 [0-4] 8b 85 a4 fc ff ff 03 85 d0 fd ff ff 33 d0 8b 8d ac fd ff ff 88 91 [0-4] ba 7d 22 00 00 85 d2 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAE_2147845505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAE!MTB"
        threat_id = "2147845505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8d 40 d4 c1 c8 08 29 f8 83 e8 01 31 ff 4f 21 c7 c1 c7 08 89 03 83 eb fc 83 c6 fc}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAE_2147845505_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAE!MTB"
        threat_id = "2147845505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 4d f8 8b 11 03 55 f8 a1 [0-4] 03 45 f8 89 10 8b 4d f8 81 c1 e9 03 00 00 8b 15 [0-4] 03 55 f8 33 0a a1 [0-4] 03 45 f8 89 08 eb}  //weight: 4, accuracy: Low
        $x_4_2 = {03 4d f4 8b 01 03 45 f4 03 55 f4 89 02 8b 45 f8 89 45 f0 c7 45 fc 86 7f 00 00 8b 05 [0-4] 89 45 ec 8b 55 08 03 55 f4 8b 02 33 45 ec 8b 4d 08 03 4d f4 89 01 eb}  //weight: 4, accuracy: Low
        $x_1_3 = ".ropf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zbot_BAG_2147845544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAG!MTB"
        threat_id = "2147845544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 c6 fe 83 ee ff 29 de 89 f3 6a 00 8f 01 01 31}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAG_2147845544_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAG!MTB"
        threat_id = "2147845544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {40 90 48 90 90 90 a1 70 50 40 00 30 10 ba 74 50 40 00 ff 0a b8 70 50 40 00 ff 00 eb}  //weight: 2, accuracy: High
        $x_2_2 = {b9 1a 00 00 56 0f a2 0f 31 89 c6 0f a2 0f 31 29 f0 89 45 f4 5e 81 7d f4 00 01 00 00 7f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAG_2147845544_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAG!MTB"
        threat_id = "2147845544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 c2 33 d2 b9 00 01 00 00 f7 f1 89 95 e8 fb ff ff 8b 95 e8 fb ff ff 8a 84 15 e4 fa ff ff 88 85 c0 f7 ff ff 8b 0d [0-4] 03 8d d0 f8 ff ff 0f be 11 0f be 85 c0 f7 ff ff 33 d0 8b 0d [0-4] 03 8d d0 f8 ff ff 88 11 e9}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_EH_2147846271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.EH!MTB"
        threat_id = "2147846271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b 45 08 33 d2 f7 f7 89 45 08 8d 42 37 83 fa 09 77 03 8d 42 30 88 01 41 83 7d 08 00 77 e2 8b c1 2b c6 c6 01 00 49 8a 1e 8a 11 88 19 49 88 16}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GHG_2147847794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GHG!MTB"
        threat_id = "2147847794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ca 8b 49 3c c1 a4 25 ?? ?? ?? ?? 06 8b 4c 11 78 03 ca 8b 49 0c 31 05 78 45 40 00 8a 14 11 fe ca 80 f2 2f 19 94 25 ?? ?? ?? ?? 80 fa 65 0f 84}  //weight: 10, accuracy: Low
        $x_10_2 = {33 d7 33 d6 81 a4 25 ?? ?? ?? ?? 55 1c 00 00 51 19 94 25}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_EM_2147847858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.EM!MTB"
        threat_id = "2147847858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {75 bb 92 76 b8 91 78 b6 90 7a b4 8f 7b b1 8d 7d af 8c 7f ac 8b 80 aa 8a 82 a8 88 84 a5 87 85 a3 86 87 a0 85 89 9e 83 8b 9c 82 8c 99 81 8e 97 80 90 94 7e 91 92 7d 93 8f 7c 95 8d 7a 96 8b 79 98}  //weight: 3, accuracy: High
        $x_2_2 = "tguxwioonrbgaalopkcvj" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_EM_2147847858_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.EM!MTB"
        threat_id = "2147847858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "de-openphone.org" wide //weight: 1
        $x_1_2 = "64AD0625" ascii //weight: 1
        $x_1_3 = "drivers\\wsnpoem.sys" wide //weight: 1
        $x_1_4 = "netsh firewall add portopening TCP 6081 RPC" wide //weight: 1
        $x_1_5 = "91C38905" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAH_2147848122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAH!MTB"
        threat_id = "2147848122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 5a c1 c2 0a c1 ca 02 c7 01 ?? ?? ?? ?? 31 01 83 c1 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAH_2147848122_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAH!MTB"
        threat_id = "2147848122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ee 02 8d 76 01 29 de 31 db 4b 21 f3 c7 42 ?? ?? ?? ?? ?? 31 32}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAH_2147848122_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAH!MTB"
        threat_id = "2147848122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b ec c7 05 [0-4] 7e d2 4a 50 c7 05 [0-4] 61 00 00 00 c7 05 [0-4] e6 ff be 09 c7 05 [0-4] 62 00 00 00 c7 05 [0-4] a0 f0 76 e0 c7 05 [0-4] 63 00 00 00 c7 05 [0-4] 3e a2 aa ac c7 05 [0-4] 64 00 00 00 c7 05 [0-4] ca f3 a2 81}  //weight: 2, accuracy: Low
        $x_2_2 = {68 3e a2 aa ac 68 7e d2 4a 50 68 ca f3 a2 81 68 88 98 8a 59 68 8e d7 be 43 68 00 3a b4 93 68 40 49 5a fd 68 66 3d 7e 05 68 ca f3 a2 81 68 88 98 8a 59}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GJL_2147848223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GJL!MTB"
        threat_id = "2147848223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c6 89 45 e4 69 c0 ?? ?? ?? ?? 35 ?? ?? ?? ?? 29 45 08 8b 45 08 33 d2 b9 ?? ?? ?? ?? f7 f1 8b 45 f4 85 d2 0f 84}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AZB_2147848498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AZB!MTB"
        threat_id = "2147848498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 e2 d9 8d be 00 60 05 00 8b 07 09 c0 74 45 8b 5f 04 8d 84 30 60 9a 05 00 01 f3 50 83 c7 08 ff 96 24 9b 05 00 95 8a 07 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AZB_2147848498_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AZB!MTB"
        threat_id = "2147848498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e1 02 d3 e0 c1 e1 03 23 c8 33 ce f7 e3 83 ef 72 49 c1 e0 04 23 d9}  //weight: 1, accuracy: High
        $x_2_2 = {f7 e1 33 f6 d3 ee 0b cf 42 d1 e9 d3 e6 8d 0c 80 d3 e3 8d 93 da 00 00 00 33 c9 8d 0c 89 ba 95 15 de f4 c1 e0 04 42 81 ef 7c 2b 00 00 c1 e7 05 83 e8 24}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AZB_2147848498_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AZB!MTB"
        threat_id = "2147848498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {a6 8a 5b 01 c3 45 60 88 5d 0b c3 a5 ?? 3a 5a 01 c3 56 31 83 ?? ?? ?? ?? 3a f2 42 c3 5c 33 d2 c3 42 5f 1b d2 c3}  //weight: 3, accuracy: Low
        $x_2_2 = {4a 96 83 f8 02 c3 30 88 ?? ?? ?? ?? 83 e8 03 c3 d7 37 0f b6 09 c3 a9 c1 e0 08 c3 b4 14 03 c1}  //weight: 2, accuracy: Low
        $x_1_3 = "windows\\EPa.exe.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AZB_2147848498_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AZB!MTB"
        threat_id = "2147848498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 0f fe c6 45 12 ac c6 45 9d 92 c6 45 0d b8 c6 45 b8 ea c6 45 3e 3e c6 45 76 8f c6 45 fc bf c6 45 65 b0 c6 45 cd 24 c6 45 58 24 c6 45 94 d4 c6 45 f5 f8 c6 45 dc 51 c6 45 a8 fa c6 45 d4 fb c6 45 3b 30 c6 45 81 55 c6 45 bc f8 c6 45 57 03 c6 45 fb f0 c6 45 2a c5 c6 45 ad 4a c6 45 33 cb c6 45 93 28 c6 45 8e f0 c6 45 39 b9 c6 45 f7 e9 c6 45 18 1f c6 45 2b e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAI_2147849285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAI!MTB"
        threat_id = "2147849285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "A92CbCv8cdMjX6IGck6m0a3Cq2orExn7TMh3qbSZK2fBHF" ascii //weight: 2
        $x_2_2 = "MPPGJwveOEw0EEMgpj9gR9fOqAUuyPMZehJspwNJfvg0AgOkE" ascii //weight: 2
        $x_2_3 = "9e0XeyjhyYDKyXGUifuk4ogF6cHQGJ5" ascii //weight: 2
        $x_2_4 = "ickeehvuK1DjQF93x1um5NwnfzVnYt3C2SBzlEL0MBa1B8FdueWyu6dbAxEod4Z8sMlUbPmVaZ1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_EN_2147849811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.EN!MTB"
        threat_id = "2147849811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8d 0c 02 8b 55 f4 89 d0 c1 e0 02 01 d0 c1 e0 03 01 c8 05 f8 00 00 00 89 45 e0 8b 45 e0 8b 50 10 8b 45 08 8b 00 89 c1 8b 45 e0 8b 40 14 01 c8 89 c3 8b 45 e4 8b 48 34 8b 45 e0 8b 40 0c 01 c8}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_EN_2147849811_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.EN!MTB"
        threat_id = "2147849811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Proxy-Connection" ascii //weight: 1
        $x_1_2 = "|zkrvvcnmaebNUf" ascii //weight: 1
        $x_1_3 = "dcm\\n\\TS" ascii //weight: 1
        $x_1_4 = "bapbXlUR" ascii //weight: 1
        $x_1_5 = "fbmnX\\VW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_EN_2147849811_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.EN!MTB"
        threat_id = "2147849811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SonOfSon.EXE" wide //weight: 1
        $x_1_2 = "My Son is my Son" wide //weight: 1
        $x_1_3 = "[ESC] Stop" wide //weight: 1
        $x_1_4 = "[DEL] Clear list" wide //weight: 1
        $x_1_5 = "Auto Clicker Ver 1.0" ascii //weight: 1
        $x_1_6 = "MFC42" ascii //weight: 1
        $x_1_7 = "mouse_event" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DAL_2147850085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DAL!MTB"
        threat_id = "2147850085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 21 c5 6e 64 07 8c 1d 98 0f ad 62 a6 1f 7b 13 b8 fa 6a 5e 7e e7 42 b5 e4 89 b2 ac 89 96 dc 5c f8 96 b3 80 ab 9c 2e 5c ea 24 48 1c 1c f2 a1 bd 86 84}  //weight: 1, accuracy: High
        $x_1_2 = {1c 1a 74 09 3a 8c 21 4f 0c 0a 33 20 b1 0b 22 6f df 22 45 ce 38 a9 7c 40 20 6f 3d 33 ac 99 47 86 44 53 2c 20 45 0a 22 4b}  //weight: 1, accuracy: High
        $x_1_3 = {10 31 eb de c0 b1 43 20 6c e0 62 27 e8 86 60 90 c8 70 a9 20 1b 7d 3e 6b 02 83 77 4b 75 9c 65 38 a0 86 2a b4 c4 80 e6 3c be 03 93 87 9b ee b8 6d 98 a8 59 a3 90 72 54}  //weight: 1, accuracy: High
        $x_1_4 = {95 1c 9e 5e 31 24 47 40 38 37 2d 63 44 35 fc ff b9 b1 be a7 ce c4 22 ec 28 8a 4c f2 f8 cf 9f 12 3c 04 d1 ee ec bb d0 14 5c 33 d3 8e e7 4b 34 93 f2 d7 7b 4d 01 2b 93 a3 b7}  //weight: 1, accuracy: High
        $x_1_5 = {8a cf 40 a8 0f 92 1a 5f 45 d0 da 19 a0 ad 60 2d 7c 56 0a 54 ef b6 9d 81 29 90 b5 43 06 98 94 3c dc c9 23 0c 5c 08 e2 57 98 ad 10 53 cc b6 4e 74 3a 13 f6 a2 0b c9 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DAM_2147850086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DAM!MTB"
        threat_id = "2147850086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 fa a2 99 d2 37 9c 55 eb 69 a8 d2 cc 4f 92 09 38 81 da 3a ec e9 bc e9 06 f9 21 93 dc 09 9d 81 fd 60 56 59 6d 6a ba 6f d6 e0 51 1f 75 91 f1 4a}  //weight: 1, accuracy: High
        $x_1_2 = {41 fe 45 e7 a9 ea 33 a9 a9 da 02 f9 aa 1b 60 82 7d 70 ac ad ae af 0b 99 6c 92 2f 97 64 de 12 74 58 ce 1a 47 ad 1f f3 c4 01 a8 56 ba 4c 49 e3 bb d1 dd b8 59 5c fc ac}  //weight: 1, accuracy: High
        $x_1_3 = {f8 ea 81 c2 10 8b 0a a5 90 00 29 0f ba c9 f3 4b 7f 6d 68 e9 7e 19 09 01 11 13 bd 53 03 c2 7c 50 df 31 57 a6 e8 79 12 44 f7 80 0d 01 ea 21 d7 15 15 b8 55 40 d3 c8 01 4e d4 c3}  //weight: 1, accuracy: High
        $x_1_4 = {1d 36 2e a4 66 2c 44 02 03 9c 1f ff 34 24 e9 84 50 08 11 06 4b 8e fb 33 03 b6 83 f8 02 c1 0e 87 30 19 98 0e 17 76 dd 18 1e bb 1a 0a ea 0c 82 40 4b 1b 01 ab 9e 14}  //weight: 1, accuracy: High
        $x_1_5 = {7d 5e b2 e4 9e f0 f9 44 00 57 03 86 09 2d b6 60 31 01 72 f2 62 73 22 e9 46 3e f2 53 b5 eb 8e 1e 5c 91 80 58 68 d1 47 12 5f 33 e2 49 b4 ae 38 3c 6d c1 25 8d b5 3e 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DAN_2147850603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DAN!MTB"
        threat_id = "2147850603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vqJSnLqUpPvMgVnex7ksyxSgYevSFpzsf1xvBktuyaDTnKifjDswGyHrkGv8vQvGKEBZoUCHczK6m5gkaPYa5z0" ascii //weight: 1
        $x_1_2 = "KzjiWk6xmENgdzaieKEMYyH8mjQEu1KJUgizEAYWamqUidRcHsEiulChgwzx5V8lBpRmTen0Z8cslDCszm" ascii //weight: 1
        $x_1_3 = "CjvwhChwM4ORwpgocA5HPQ7pjtiKXW3Zvn2UIWHBaUnI2sf49VwjRUygGhiwroiHUuNH" ascii //weight: 1
        $x_1_4 = "H67qWpwIXUHtyBJc6l8qPnt2h02sQyjscmzkgOU2Z84DRLAWUa3r9k6Q4Wa0DG" ascii //weight: 1
        $x_1_5 = "UtL0U87fwWr6baMzX468pKyf0qIYtBd75R5yQu69858NgnJJL6oUfJtFXLtKmF4C5F1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DAO_2147850620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DAO!MTB"
        threat_id = "2147850620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 24 6d 48 bf 33 6d b9 65 a1 d5 47 33 10 08 33 32 33 bf 48 bf a1 89 6d 48 08 b9 bf 33 47 a5 0f 24 d5 a5 e6 a1 10 6d 10 32 10 32 a5 a5 24 6d 33 b9 47 6d}  //weight: 1, accuracy: High
        $x_1_2 = "T7am5yHMaLe7oPJEmsnnPXLV7lIBjSggamnJI6KnsHPt8a" ascii //weight: 1
        $x_1_3 = "F4OtcnFEPNipdYu5GRB1Li5frSsA1A6gnmVCdWVSFuwrb1UWbiuL8V" ascii //weight: 1
        $x_1_4 = "xE8LjnJri6rLlaviCJUv6GXneKeoUhagVeueDLxV3eEDaeNqW874b" ascii //weight: 1
        $x_1_5 = "newiat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RPY_2147851479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RPY!MTB"
        threat_id = "2147851479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 56 68 00 00 04 00 ff 15 ?? ?? ?? 00 8b 4c 24 10 83 c1 0a 51 6a 08 50 ff 15 ?? ?? ?? 00 ff 74 24 10 8b f8 53 57 e8 8c 36 00 00 83 c4 0c 56 56 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "156.236.70.181" ascii //weight: 1
        $x_1_3 = "Loader.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_Z_2147851644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.Z!MTB"
        threat_id = "2147851644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ff 00 74 ?? 83 ef 04 83 c6 04 8b 4e fc 89 8b ?? ?? ?? ?? 83 c3 04 81 ab}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DAQ_2147852441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DAQ!MTB"
        threat_id = "2147852441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 31 23 5c c0 86 14 a0 fc 91 58 84 1e 62 02 82 84 08 3d 3f cb ac 70 c3 75 d2 3e b6 dc 74 1a 26 94 6b f1 6d 77 0e 63 3d 6a 33 2c 6d 25 ca f6 77 db 5b a1 ec 74 2e f8 e1 df c8 d9 5b df 8c e3 f1 5a 53 ba 51 2c 03 e5 c4 80 52 40 c1 4e 52 9f}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0c 4f 35 f5 6a 9a c8 1f 74 a1 9c 47 13 ed 89 fa 12 be 75 ec dc c6 c2 da b0 92 74 6e dc 92 4b 57 7b b1 79 54 b1 e3 bb cd ba 8f f1 d1 18 62 b4 4a 6b b3 c5 1e 7a c9 a9 d4 a5 bc f5 24 78 52 e4 64 51 a6 7a 7e 66 49 2f 69 4b 55 eb 87 da 0e 4e}  //weight: 1, accuracy: High
        $x_1_3 = {7d de f3 71 d7 d8 a9 58 1f 8e 03 f5 da 50 5a 58 ec 02 45 ae 17 52 9a b4 62 32 35 41 bf 78 9c 07 e1 93 bb ed b6 ee 62 37 cc 33 25 6c d7 9b 83 33 2a 3d 08 bd 40 91 3c 2e 72 6e a3 50 5c f4 35 cb 07 56 94 e4 6e 72 38 51 b5 d8 93}  //weight: 1, accuracy: High
        $x_1_4 = {6c 12 35 71 b6 18 92 17 ed a3 0f 29 13 9a a5 c8 23 27 bb 78 92 a5 ff 08 9d 57 ce 77 de e6 47 b3 79 4d 4d e2 68 d4 3e 41 aa d4 26 11 cb 4a 56 11 49 ce b1 e0 db 18 a5 61}  //weight: 1, accuracy: High
        $x_1_5 = {ed 96 bf 16 26 2b 2f fe 1d 33 5f fd 6d 07 90 47 4f 94 3a 4d 45 98 92 4b dd 08 2e 93 76 39 2b 48 4c 81 51 cd f6 6d ff fc 66 a2 03 5c 80 c0 74 96 9f 91 e3 04 16 32 2a e9 c0 38 03 9e 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_ASAF_2147888946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.ASAF!MTB"
        threat_id = "2147888946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c9 81 c1 3a 8e 00 00 81 e1 38 5c 00 00 c1 e1 0c 81 f1 26 51 00 00 c1 e1 04 69 c9 14 79 00 00 81 f9 b9 d3 d4 59 0f 86}  //weight: 1, accuracy: High
        $x_1_2 = "?KevdnSbefedro@@YGHHI@Z" ascii //weight: 1
        $x_1_3 = {68 7c 32 00 00 68 59 4e 00 00 68 6f 87 00 00 68 b4 35 00 00 68 85 67 00 00 68 c2 34 00 00 68 92 57 00 00 68 df 70 00 00 68 ec 67 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = "Evknxnyjtzyf.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_DAZ_2147891267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.DAZ!MTB"
        threat_id = "2147891267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 80 f9 27 75 03 8a ?? ?? ?? ?? 10 57 89 01 eb 25 84 d2 74 0a 0f be 08 0f b6 fa 3b cf eb}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c6 33 c9 85 c0 0f 9f c1 f7 d8 1b c0 8d 4c 09 ff 23 c1 5f 5e 5b 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GPA_2147891436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GPA!MTB"
        threat_id = "2147891436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 d1 0f b6 d2 66 89 14 47 40 46 8a 16 84 d2 75 ef}  //weight: 2, accuracy: High
        $x_2_2 = {80 b4 05 00 ff ff ff 5c 40 3b c6 7c f3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_ASB_2147891639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.ASB!MTB"
        threat_id = "2147891639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 1f f9 61 f7 90 99 a8 28 fd 96 e3 37 66 11 ac f9 7d 9d 29 76 1b 38 da ae 14 a8 66 c3 39 e7 97 74 ff 7a d8 5e 85 d1 90 11 c7 03 a8 17 88 90 f4 2d f5 df 10 7d a5 14 9f c9 21 6a f7 49 cf 70 23 fd 80 4d ef 6d 11 02}  //weight: 2, accuracy: High
        $x_2_2 = {29 a1 73 00 d2 1e 11 e7 ff 6c ae 35 89 ff 5d 0d 2e f6 e9 78 26 20 4c f7 d2 51 9f ee 52 b0 1b 64 d6 ff aa 5e 23 51 a5 19 00 3a c6 16 c6 12 06 85 49 ff e3 28 6f b0 a6 65 51 e8 a9 d9 92 d4 0a 96 d9 1b 5c eb 96 30 47}  //weight: 2, accuracy: High
        $x_1_3 = {e0 00 0f 01 0b 01 02 32 00 40 03 00 00 2e 00 00 00 00 00 00 00 10 00 00 00 10 00 00 00 50 03}  //weight: 1, accuracy: High
        $x_1_4 = ".vmp0" ascii //weight: 1
        $x_1_5 = ".vmp1" ascii //weight: 1
        $x_1_6 = ".vmp2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_ASC_2147892572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.ASC!MTB"
        threat_id = "2147892572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bf e8 48 d7 a8 79 c9 6f 32 43 fe 47 39 43 d8 50 23 63 d5 5a 32 56 d9 28 bf 11 4b d7 a8 79}  //weight: 1, accuracy: High
        $x_1_2 = {33 f9 c4 00 cc 67 81 b1 ce 74 33 96 2b ee 43 b1 25 84 b7 71 27 5a 29 34 29 e7 d9 bb ff bd 58 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zbot_AMAD_2147892665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AMAD!MTB"
        threat_id = "2147892665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Proxy-Connection" ascii //weight: 1
        $x_1_2 = "=-=-PaNdA!$2" ascii //weight: 1
        $x_1_3 = "-!-@hj01N./1" ascii //weight: 1
        $x_1_4 = {8d 3c 01 8a c8 02 c9 b2 f6 2a d1 00 17 eb ?? 8a d0 02 d2 03 c8 80 c2 07 00 11 40 3b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_ASD_2147894706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.ASD!MTB"
        threat_id = "2147894706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UbC9AB3z.exe" wide //weight: 1
        $x_1_2 = "IZyIyDgy.exe" wide //weight: 1
        $x_1_3 = "74Y9qEpU.exe" wide //weight: 1
        $x_1_4 = "unnIJOmo.exe" wide //weight: 1
        $x_1_5 = "SqkA1Xa86EU.txt" ascii //weight: 1
        $x_1_6 = "DuICx7Fzv5.ini" ascii //weight: 1
        $x_1_7 = "EvJDU7FAwq.cfg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GIS_2147896095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GIS!MTB"
        threat_id = "2147896095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 0d 9c 4a 40 00 8b 15 94 4a 40 00 8b 45 08 89 04 8a 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d ?? ?? ?? ?? 33 c0 eb 03 83 c8 ff 5d c3}  //weight: 10, accuracy: Low
        $x_10_2 = {8b d0 8b 5d f0 33 c0 42 8b 0a 40 fe c1 fe c9 75 f6 48 c3}  //weight: 10, accuracy: High
        $x_1_3 = "C:\\virus.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GIM_2147896096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GIM!MTB"
        threat_id = "2147896096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 5d d8 c1 cb 13 0f b6 03 43 43 c1 cb ?? 89 5d d8 b9 18 00 00 00 c1 c1 03 3b c1 72 23 2b c1 03 c0 8b 55 fc 81 c2 ?? ?? ?? ?? 03 d0 03 d0 81 c2 ?? ?? ?? ?? 89 55 fc 85 c0 75 c5 c3}  //weight: 10, accuracy: Low
        $x_1_2 = "conwur.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SMT_2147896097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SMT!MTB"
        threat_id = "2147896097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {50 8b ec 8b 4d 10 33 d2 8b 75 04 8b 36 03 f3 33 c0 50 c1 c8 07 31 04 24 ac 84 c0 75 f5 58}  //weight: 10, accuracy: High
        $x_1_2 = ".obchqb" ascii //weight: 1
        $x_1_3 = "oa9RLVP5J" ascii //weight: 1
        $x_1_4 = "oAKWEMYE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GC_2147896098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GC!MTB"
        threat_id = "2147896098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 fc 8b 4d fc 33 c6 33 ce 8d 8c 08 b6 4a ca 0e 8b 45 f8 33 d2 f7 f1 8b 45 f4 8b 4d fc 33 c6 33 ce 2b c1 3b d0 0f 85 3b 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "scxhgfeeUdgq\\cekveje.pdb" ascii //weight: 1
        $x_1_3 = "IDUoijkND.txt" ascii //weight: 1
        $x_1_4 = "qwQfhsdKSnD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GQ_2147896099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GQ!MTB"
        threat_id = "2147896099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 72 28 6a 18 59 33 ff 33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12 75 db 89 5d fc 8b 45 fc a3 b4 ab 40 00 5f 5e 5b 8b e5 5d c3}  //weight: 10, accuracy: High
        $x_10_2 = {8b 45 fc 0f be 0c 10 8b 55 f4 0f be 82 98 a5 40 00 33 c1 8b 4d f4 88 81 98 a5 40 00 eb 88}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zbot_PABU_2147897557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.PABU!MTB"
        threat_id = "2147897557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0e 03 cb b8 00 40 00 00 c1 c0 14 03 f0 c1 c1 08 89 4d 94 03 d5 52 e8 ?? ?? ?? ?? 56 59 5a 2b d5 8b 45 a8 85 c7 c1 c0 16 03 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_RMT_2147897570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.RMT!MTB"
        threat_id = "2147897570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {09 f3 42 c0 de e5 15 65 ce 0c 79 b2 59 35 fa 31 84 76 81 ba 5f 10 8f 14 55 98 9b ec e1 e4}  //weight: 10, accuracy: High
        $x_10_2 = {8b 06 8a e9 32 c5 fe c1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_FFH_2147897571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.FFH!MTB"
        threat_id = "2147897571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 10 8b 14 85 ?? ?? ?? ?? 33 c0 8b cf 40 c1 e9 02 3b c8 76 08 31 14 83 40 3b c1 72 f8}  //weight: 10, accuracy: Low
        $x_1_2 = "evedbonline.com" ascii //weight: 1
        $x_1_3 = "alamx.com" ascii //weight: 1
        $x_1_4 = "gffos.exe" ascii //weight: 1
        $x_1_5 = "roperns.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SPD_2147900525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SPD!MTB"
        threat_id = "2147900525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 f8 83 c2 04 89 55 f8 8b 45 f8 3b 45 f0 73 38 8b 0d ?? ?? ?? ?? 03 4d f8 8b 11 03 55 f8 a1 ?? ?? ?? ?? 03 45 f8 89 10 8b 4d f8 81 c1 e9 03 00 00 8b 15 ?? ?? ?? ?? 03 55 f8 33 0a a1 ?? ?? ?? ?? 03 45 f8 89 08 eb b7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SPY_2147900574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SPY!MTB"
        threat_id = "2147900574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 4b 8b d8 85 c0 90 58 2b f0 50 8b d8 51 8b 0f 8b 06 33 c1 46 88 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_ASE_2147900598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.ASE!MTB"
        threat_id = "2147900598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {64 69 64 6c 65 72 35 00 1a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 43 68 69 6e 61 6d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_GZZ_2147905109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.GZZ!MTB"
        threat_id = "2147905109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {12 29 42 fe 0c 66 30 dd 61 79}  //weight: 5, accuracy: High
        $x_5_2 = {80 40 88 44 11 80 ?? ?? ?? ?? 30 40 00 44 22}  //weight: 5, accuracy: Low
        $x_1_3 = "@gu_idata" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_PADU_2147908446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.PADU!MTB"
        threat_id = "2147908446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 f2 83 8b 45 50 03 fa 4b 89 0e ba 7b 00 ae 7c 81 c2 89 ff 51 83 03 f2 85 db 0f 84 d3 06 00 00 8b 0f 8b 55 d4 81 f2 c1 89 c0 0f 03 fa 4b 89 0e ba 45 55 ff 85 81 c2 bf aa 00 7a 03 f2 85 db 75 ba}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_ASF_2147908977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.ASF!MTB"
        threat_id = "2147908977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 2b c2 03 c2 33 01 89 03 83 c1 04 47 8b c7 2b 45 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 04 6a 40 68 00 30 00 00 51 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_ASGA_2147909741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.ASGA!MTB"
        threat_id = "2147909741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b7 ff 84 0f 0b f8 55 8b 2d 78 5a 3f e8 8c 62 53 5a e9 8d 88 1e 5a db ff 76 fb 5d c3 90 2b 1b 39 03 07 7b b9 0b 23 63 7a 89 8d}  //weight: 2, accuracy: High
        $x_2_2 = {17 44 e8 6b 0e 4c 8b 45 d0 35 41 db dd fd 6f 7b 01 2d cd db 74 f0 89 85 5c 19 e9 3d 10 93 0b c3 57 b3 fc db 7e b8 d8 ac c8 13 14 34 39 57}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_AZT_2147934843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.AZT!MTB"
        threat_id = "2147934843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {23 02 20 68 25 20 02 20 68 1d 20 02 20 68 15 20 02 20 e9 0d ee ff ff 32 9c 68 ?? ?? ?? ?? 68 25 20 02 20 68 1d 20 02 20 68 15 20 02 20}  //weight: 3, accuracy: Low
        $x_2_2 = {d0 8b d8 c3 a1 8b 73 3c c3 8f 03 f3 c3 aa 8b 86 80 00 00 00 c3 f3 fd 8b 44 18 10 c3 41}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_PAZB_2147936650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.PAZB!MTB"
        threat_id = "2147936650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 ca 8b 15 28 9f 41 00 03 95 ?? ?? ?? ?? 88 0a 8b 85}  //weight: 2, accuracy: Low
        $x_2_2 = {83 f1 44 8b 15 28 9f 41 00 03 95 ?? ?? ?? ?? 0f be 02 33 c1 8b 0d 28 9f 41 00 03 8d ?? ?? ?? ?? 88 01 8b 95}  //weight: 2, accuracy: Low
        $x_2_3 = {83 f2 73 a1 28 9f 41 00 03 85 ?? ?? ?? ?? 0f be 08 33 ca}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_SLY_2147938426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.SLY!MTB"
        threat_id = "2147938426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 44 24 04 50 33 db 53 53 68 28 82 41 00 68 02 00 00 80 ff 15 0c 80 41 00 3b c3 74 06 83 f8 02 0f 95 c3 8a c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAJ_2147938609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAJ!MTB"
        threat_id = "2147938609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b c1 32 d8 89 44 24 ?? 8a 84 24 ?? ?? ?? ?? 8d bc 14 ?? ?? ?? ?? 88 1f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAJ_2147938609_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAJ!MTB"
        threat_id = "2147938609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {29 c0 33 02 83 c2 04 f7 d8 83 e8 29 83 e8 02 40 29 f8 89 c7 c7 46 ?? ?? ?? ?? ?? 31 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAK_2147940154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAK!MTB"
        threat_id = "2147940154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 85 14 ff ff ff 8b 85 40 ff ff ff 8b 4d e4 8b 04 81 99 2b c2 d1 f8 89 85 3c ff ff ff 81 bd ?? ?? ?? ?? ?? ?? ?? ?? 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_EAEN_2147940171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.EAEN!MTB"
        threat_id = "2147940171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 c1 8b 55 fc 8b 45 0c 01 d0 89 ca 88 10 83 45 fc 01 8b 45 fc 3b 45 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAL_2147941286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAL!MTB"
        threat_id = "2147941286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f dc db 0f 60 f1 66 0f e9 d3 31 37 0f e5 ed}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_BAM_2147945619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.BAM!MTB"
        threat_id = "2147945619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 cc 33 d2 b9 10 00 00 00 f7 f1 8b 45 cc 8a 88 ?? ?? ?? ?? 2a 8a ?? ?? ?? ?? 8b 55 cc 88 8a ?? ?? ?? ?? eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_MR_2147949982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.MR!MTB"
        threat_id = "2147949982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {51 8b 95 30 ce ff ff 52 8b 85 a0 cf ff ff 50 ff 95 ec cd ff ff}  //weight: 10, accuracy: High
        $x_5_2 = {8b c8 0f b7 85 c4 fc ff ff 03 05 20 89 42 00 8b 35 20 89 42 00 83 c6 01 99 f7 fe 03 c8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_NB_2147954838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.NB!MTB"
        threat_id = "2147954838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 45 fc 86 00 00 00 8b 55 0c 03 55 f4 0f b6 02 89 45 f8 c7 45 fc 86 00 00 00 8b 4d 08 03 4d f4 8a 55 f8 88 11 c7 45 fc 86 00 00 00 eb c1}  //weight: 2, accuracy: High
        $x_1_2 = {c7 45 ec 03 00 00 00 8b 4d 08 8b 51 04 83 ea 08 d1 ea 89 55 f4 8b 45 08 83 c0 08 89 45 f0 c7 45 fc 00 00 00 00 eb 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zbot_ARR_2147960032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zbot.ARR!MTB"
        threat_id = "2147960032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "copy /y \"C:\\Windows\\system\\loop.exe\" \"C:\\Program Files\\Windows NT\"> nul" ascii //weight: 20
        $x_5_2 = "SCHTASKS /Create /TN %name% /TR \"'C:\\Windows\\system\\Zloop.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

