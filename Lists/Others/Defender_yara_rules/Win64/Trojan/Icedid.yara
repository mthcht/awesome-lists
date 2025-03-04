rule Trojan_Win64_Icedid_SQ_2147781660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.SQ!MTB"
        threat_id = "2147781660"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c1 03 0d ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 44 ?? ?? 44 ?? ?? 44 ?? ?? 01 d1 2b 4c 24 ?? 48 ?? ?? 8a 04 08 42 ?? ?? ?? 49 ?? ?? 88 44 1d ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_SQ_2147781660_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.SQ!MTB"
        threat_id = "2147781660"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "38"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {45 33 c9 48 ?? ?? ?? ?? 45 33 c0 33 c9 41 8d ?? ?? ff 15 ?? ?? 00 00 48 8b cb 48 8d 15 ?? ?? 00 00 85 c0 75 ?? 48 8d 15 ?? ?? 00 00 ff 15 ?? ?? 00 00 48 8d 57 04 48 8b ce ff 15 ?? ?? 00 00 ba 22 00 00 00 48 8b ce ff 15}  //weight: 20, accuracy: Low
        $x_5_2 = "c:\\ProgramData\\" ascii //weight: 5
        $x_5_3 = "sadl_64.dll" ascii //weight: 5
        $x_5_4 = "DllRegisterServer" ascii //weight: 5
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "CreateThread" ascii //weight: 1
        $x_1_7 = "SHGetFolderPathA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_MK_2147782913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.MK!MTB"
        threat_id = "2147782913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 88 04 1b 83 e1 07 8b 44 95 e0 49 ff c3 d3 c8 ff c0 89 44 95 e0 83 e0 07 8a c8 42 8b 44 85 e0 d3 c8 ff c0 42 89 44 85 e0 48 8b 5d c8 4c 3b 5d d0 73}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_MK_2147782913_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.MK!MTB"
        threat_id = "2147782913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8b 04 24 48 8b 4c 24 08 eb 21 48 ff c0 48 89 44 24 08 eb c4 eb ce 48 8b 44 24 30 48 89 04 24 eb 27 48 8b 44 24 40 48 ff c8 eb c4 8a 09 88 08 eb 23}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_MK_2147782913_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.MK!MTB"
        threat_id = "2147782913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 3c 08 8b 84 24 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 48 63 ca 48 8b 84 24 ?? ?? ?? ?? 0f b6 04 08 8b d7 33 d0 48 63 8c 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 88 14 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_MK_2147782913_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.MK!MTB"
        threat_id = "2147782913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wDnb.dll" ascii //weight: 10
        $x_1_2 = "Bh012VLJC0z" ascii //weight: 1
        $x_1_3 = "ChAxTmVaL" ascii //weight: 1
        $x_1_4 = "D0ezwQ2kXP" ascii //weight: 1
        $x_1_5 = "D5FfBQIWDz" ascii //weight: 1
        $x_1_6 = "KnyyXGLIr2Y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_MK_2147782913_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.MK!MTB"
        threat_id = "2147782913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_gat=" wide //weight: 1
        $x_1_2 = "_ga=" wide //weight: 1
        $x_1_3 = "_u=" wide //weight: 1
        $x_1_4 = "__io=" wide //weight: 1
        $x_1_5 = "_gid=" wide //weight: 1
        $x_1_6 = "Cookie: __gads=" wide //weight: 1
        $x_1_7 = "loader_dll_64.dll" ascii //weight: 1
        $x_1_8 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_GA_2147783527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.GA!MTB"
        threat_id = "2147783527"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 02 c7 44 24 ?? ?? ?? ?? ?? 48 8b 54 24 ?? 48 81 c2 01 00 00 00 48 89 54 24 ?? c7 44 24 58 ?? ?? ?? ?? 8b 4c 24 ?? 81 e9 a1 16 9f 6e 83 c1 ff 81 c1 a1 16 9f 6e 89 4c 24 ?? 83 f9 00 0f 84 ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? e9}  //weight: 10, accuracy: Low
        $x_1_2 = "PluginInit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_GB_2147783528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.GB!MTB"
        threat_id = "2147783528"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 31 f3 88 5c 24 ?? c7 44 24 [0-5] 8a 54 24 ?? 80 ea ?? 80 c2 ?? 80 c2 ?? 88 54 24 ?? c7 44 24 [0-5] 8a 54 24 ?? 48 8b 4c 24 ?? 88 11 c7 44 24 [0-5] 48 8b 4c 24 ?? 48 81 c1 01 00 00 00 48 89 4c 24 ?? c7 44 24 [0-5] 44 8b 5c 24 ?? 83 e8 ff 41 29 c3 44 89 5c 24 ?? 41 83 fb 00 0f 84 [0-4] c7 44 24 [0-5] e9}  //weight: 10, accuracy: Low
        $x_1_2 = "PluginInit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_E_2147798149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.E!MTB"
        threat_id = "2147798149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b c2 48 8d 49 01 83 e0 03 ff c2 0f b6 44 30 2c 30 41 ff 3b d7 72 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_E_2147798149_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.E!MTB"
        threat_id = "2147798149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b d2 d6 89 d1 81 c1 34 08 00 00 48 63 c9 48 69 c9 09 04 02 81 48 c1 e9 20 01 d1 81 c1 34 08 00 00 89 c8 c1 e8 1f c1 f9 06 01 c1 89 c8 c1 e0 07 29 c1 8d 04 0a 05 34 08 00 00 01 d1 81 c1 b3 08 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_ER_2147809571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.ER!MTB"
        threat_id = "2147809571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8b 43 38 48 63 93 c0 02 00 00 48 8b 4b 10 0f b6 14 0a 42 32 14 18 48 8b 43 60 41 88 14 03 48 81 7b 20 45 3b 00 00 73 12}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_ER_2147809571_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.ER!MTB"
        threat_id = "2147809571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {48 f7 fa 49 ff c0 49 83 de 1e 48 1d 90 17 00 00 4c 13 e8 48 f7 c4 e2 12 00 00 c8 45 00 00 83 04 24 01 8b 04 24}  //weight: 4, accuracy: High
        $x_1_2 = "ijniuashdyguas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_ER_2147809571_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.ER!MTB"
        threat_id = "2147809571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PluginInit" ascii //weight: 1
        $x_1_2 = "QoxgFH" ascii //weight: 1
        $x_1_3 = "ScrYsI" ascii //weight: 1
        $x_1_4 = "ibZIdLgd" ascii //weight: 1
        $x_1_5 = "lNsYsAopo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_ER_2147809571_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.ER!MTB"
        threat_id = "2147809571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hyuasbbjhas" ascii //weight: 1
        $x_1_2 = "S6CSff9" ascii //weight: 1
        $x_1_3 = "Z1a0oYSm6" ascii //weight: 1
        $x_1_4 = "eEranvp" ascii //weight: 1
        $x_1_5 = "qFYbuL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_ER_2147809571_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.ER!MTB"
        threat_id = "2147809571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AvnMiFdRYm" ascii //weight: 1
        $x_1_2 = "Bnyiutt27" ascii //weight: 1
        $x_1_3 = "Et2w8GAiux" ascii //weight: 1
        $x_1_4 = "Ezxd0Pz3" ascii //weight: 1
        $x_1_5 = "KKNxAPf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_ER_2147809571_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.ER!MTB"
        threat_id = "2147809571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PQaiX13cFFl" ascii //weight: 1
        $x_1_2 = "Tz9uFAbe" ascii //weight: 1
        $x_1_3 = "X6jvuc6JZr" ascii //weight: 1
        $x_1_4 = "Xw3SZuEMX" ascii //weight: 1
        $x_1_5 = "hYp7oyIIgC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_ER_2147809571_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.ER!MTB"
        threat_id = "2147809571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OAvhcpVAGh" ascii //weight: 2
        $x_2_2 = "aGZ4TIwku4wPS7HBdYm3Z7sd6rbYH69jE" ascii //weight: 2
        $x_1_3 = "PluginInit" ascii //weight: 1
        $x_1_4 = "RACmui" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_ER_2147809571_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.ER!MTB"
        threat_id = "2147809571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hghcgxashfgfsfgdf" ascii //weight: 1
        $x_1_2 = "HvG4XE9pNyilML8w" ascii //weight: 1
        $x_1_3 = "Mb1ROLbm6" ascii //weight: 1
        $x_1_4 = "T2eD3awoBzACC" ascii //weight: 1
        $x_1_5 = "U6kxKJB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_ER_2147809571_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.ER!MTB"
        threat_id = "2147809571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PluginInit" ascii //weight: 1
        $x_1_2 = "GhostScript" ascii //weight: 1
        $x_1_3 = "ImageMagick" ascii //weight: 1
        $x_1_4 = "xakep.ru" ascii //weight: 1
        $x_1_5 = "svgUrl" ascii //weight: 1
        $x_1_6 = "bauCMR.dll" ascii //weight: 1
        $x_1_7 = "OkpvVSfdkT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_ER_2147809571_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.ER!MTB"
        threat_id = "2147809571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 50 ff 0f af d0 f7 d2 83 ca fe 83 fa ff 0f 94 c0 41 83 f9 0a 0f 9c c1 30 c1 41 ba a1 e6 40 89 b8 e3 0e 41 e1 41 0f 45 c2 83 fa ff 0f 94 44 24 06 41 b8 e3 0e 41 e1 44 0f 45 d0 41 83 f9 0a 0f 9c 44 24}  //weight: 10, accuracy: High
        $x_3_2 = "MgkrvoiqjhbreotbZcfkwjgjnvju" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_EK_2147826132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.EK!MTB"
        threat_id = "2147826132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 01 8b 4c 24 04 eb}  //weight: 1, accuracy: High
        $x_1_2 = {33 c8 8b c1 eb}  //weight: 1, accuracy: High
        $x_1_3 = {48 63 0c 24 48 8b 94 24 80 00 00 00 e9}  //weight: 1, accuracy: High
        $x_1_4 = {88 04 0a e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_EK_2147826132_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.EK!MTB"
        threat_id = "2147826132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {4d 0f a4 cf 26 48 69 f6 21 09 00 00 e4 3f e4 b1 48 81 c5 83 0c 00 00 e6 90 48 c1 ef 8f 48 8b 04 24}  //weight: 4, accuracy: High
        $x_1_2 = "bhjadsgvtyashjk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_EK_2147826132_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.EK!MTB"
        threat_id = "2147826132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IOFPpk3" ascii //weight: 1
        $x_1_2 = "JU6dTgl" ascii //weight: 1
        $x_1_3 = "MIQjXKZ" ascii //weight: 1
        $x_1_4 = "MuzOKyA" ascii //weight: 1
        $x_1_5 = "T6a1mkTrIS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_EK_2147826132_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.EK!MTB"
        threat_id = "2147826132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALj7MF" ascii //weight: 1
        $x_1_2 = "CboBju39" ascii //weight: 1
        $x_1_3 = "HRh6FCQ91Rr" ascii //weight: 1
        $x_1_4 = "Orxf7f" ascii //weight: 1
        $x_1_5 = "QzYH5YPLFAp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_EK_2147826132_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.EK!MTB"
        threat_id = "2147826132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateMutexW" ascii //weight: 1
        $x_1_2 = "OpenSemaphoreW" ascii //weight: 1
        $x_1_3 = "VirtualAllocEx" ascii //weight: 1
        $x_1_4 = "yuagsfbvaysfhjaysufa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_EK_2147826132_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.EK!MTB"
        threat_id = "2147826132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DtHcrXaysqWuvoK" ascii //weight: 1
        $x_1_2 = "ImvbzCTEWHxzhKWN" ascii //weight: 1
        $x_1_3 = "JObbpDBDvEDLl" ascii //weight: 1
        $x_1_4 = "NkDWbpuplDrQSO" ascii //weight: 1
        $x_1_5 = "PluginInit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_EK_2147826132_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.EK!MTB"
        threat_id = "2147826132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fuadsyguasgduhaisudjyuagsdua" ascii //weight: 1
        $x_1_2 = "browserInfo" ascii //weight: 1
        $x_1_3 = "set-link-target" ascii //weight: 1
        $x_1_4 = "WaitForSingleObjectEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_CB_2147838198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.CB!MTB"
        threat_id = "2147838198"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DxWrKgnExq.dll" ascii //weight: 10
        $x_10_2 = "MqZzdNbmQL.dll" ascii //weight: 10
        $x_1_3 = "hML_DefaultCurrent" ascii //weight: 1
        $x_1_4 = "hML_ExpatVersion" ascii //weight: 1
        $x_1_5 = "hML_ExpatVersionInfo" ascii //weight: 1
        $x_1_6 = "hML_StopParser" ascii //weight: 1
        $x_1_7 = "hmlGetUtf16InternalEncoding" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Icedid_CB_2147838198_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.CB!MTB"
        threat_id = "2147838198"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "nXIjCIo.dll" ascii //weight: 10
        $x_10_2 = "wXXfchN.dll" ascii //weight: 10
        $x_1_3 = "naturaleftouterightfullinnercross" ascii //weight: 1
        $x_1_4 = "e3_win32_write_debug" ascii //weight: 1
        $x_1_5 = "hqlite3_auto_extension" ascii //weight: 1
        $x_1_6 = "hqlite3_backup_finish" ascii //weight: 1
        $x_1_7 = "hqlite3_backup_init" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Icedid_RPL_2147841146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.RPL!MTB"
        threat_id = "2147841146"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 c7 84 24 18 03 00 00 6b 00 66 c7 84 24 1a 03 00 00 65 00 66 c7 84 24 1c 03 00 00 72 00 66 c7 84 24 1e 03 00 00 6e 00 66 c7 84 24 20 03 00 00 65 00 66 c7 84 24 22 03 00 00 6c 00 66 c7 84 24 24 03 00 00 33 00 66 c7 84 24 26 03 00 00 32 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 f7 ec c1 fa ?? 8b c2 c1 e8 ?? 03 d0 49 63 c4 41 83 c4 ?? 48 63 ca 48 6b c9 ?? 48 03 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Icedid_RPX_2147844590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Icedid.RPX!MTB"
        threat_id = "2147844590"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Icedid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 84 24 20 01 00 00 45 8b 40 70 8b 0c 0a 41 2b c8 81 f1 ?? ?? ?? ?? 48 8b 94 24 20 01 00 00 8b 04 02 0f af c1 b9 04 00 00 00 48 6b c9 01 48 8b 94 24 20 01 00 00 89 04 0a b8 04 00 00 00 48 6b c0 01 b9 04 00 00 00 48 6b c9 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

