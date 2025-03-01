rule Trojan_Win32_PrivateLoader_GBF_2147836911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PrivateLoader.GBF!MTB"
        threat_id = "2147836911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 d8 8b 14 04 8d b6 ?? ?? ?? ?? 0f b7 c3 89 16 86 c0 d3 f0 8b 07 66 3b df f5 81 c7 04 00 00 00 33 c3 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PrivateLoader_GFH_2147841838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PrivateLoader.GFH!MTB"
        threat_id = "2147841838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 45 dc c6 45 fe 45 33 c1 69 c0 00 b3 ff ff 66 89 45 f0 eb 2f}  //weight: 10, accuracy: High
        $x_10_2 = {99 8b f0 a1 ?? ?? ?? ?? 33 d1 33 f0 2b c6 8b 75 e0 1b ca 8b 15 ?? ?? ?? ?? a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PrivateLoader_EC_2147843309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PrivateLoader.EC!MTB"
        threat_id = "2147843309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BATTC.SYS" ascii //weight: 1
        $x_1_2 = "_PLeWIF-PEB" ascii //weight: 1
        $x_1_3 = "AVI LIST" ascii //weight: 1
        $x_1_4 = "hdrlavih8" ascii //weight: 1
        $x_1_5 = "Themida" wide //weight: 1
        $x_1_6 = "AcroCEF.exe" wide //weight: 1
        $x_1_7 = "21.7.20099.454979" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_PrivateLoader_RPX_2147846918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PrivateLoader.RPX!MTB"
        threat_id = "2147846918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f5 66 3b ee 89 75 bc 8b f7 f6 c1 a9 d3 e6 8b 4d 0c 66 3b fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PrivateLoader_RPX_2147846918_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PrivateLoader.RPX!MTB"
        threat_id = "2147846918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 8d 84 24 ?? ?? 00 00 50 ff d6 8d 8c 24 ?? 00 00 00 51 ff d7 6a 00 6a 00 ff d3 8d 94 24 ?? ?? 00 00 52 6a 00 ff d5 83 6c 24 10 01 75 ac}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PrivateLoader_GMF_2147888606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PrivateLoader.GMF!MTB"
        threat_id = "2147888606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fe c2 d0 ca c0 c1 a1 32 da 80 f1 cc 8b 04 14}  //weight: 10, accuracy: High
        $x_10_2 = {89 07 d2 c5 8d b6 ?? ?? ?? ?? d2 ed 8b 0e 33 cb 8d 89 ?? ?? ?? ?? f7 d1}  //weight: 10, accuracy: Low
        $x_1_3 = "@.vmp0" ascii //weight: 1
        $x_1_4 = "C3DSEsF3J" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PrivateLoader_MBIM_2147890023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PrivateLoader.MBIM!MTB"
        threat_id = "2147890023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 00 65 00 6b 00 65 00 70 00 61 00 62 00 69 00 63 00 75 00 77 00 65 00 6c 00 75 00 79 00 61 00 6c 00 75 00 74 00 65 00 6a 00 6f 00 73 00 65 00 77 00 75 00 6b 00 00 00 72 69 62 61 79 69 77 75 78 65 64 75 68 6f 64 6f 72 6f 6b 00 74 61 63 75 6b 00 00 00 70 00 75 00 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PrivateLoader_A_2147892837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PrivateLoader.A!MTB"
        threat_id = "2147892837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b f1 66 c1 ca ?? 66 85 ee 0f bb d1 8b 4d ?? 66 c1 e2 ?? 66 8b d1 f9 85 c7 66 c1 ea 05 66 85 cc f8 66 81 fd ?? ?? 66 2b ca 66 89 8c 5f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PrivateLoader_MBKS_2147894693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PrivateLoader.MBKS!MTB"
        threat_id = "2147894693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zufixuvajapidumofikoxigososusoni" ascii //weight: 1
        $x_1_2 = "vezex" ascii //weight: 1
        $x_1_3 = "nepujijotebayuni" ascii //weight: 1
        $x_1_4 = "guyebepehixutumudahivufaladovopu holelit cejebodemucefevojawe kewavesiros" ascii //weight: 1
        $x_1_5 = "huvucekafod" ascii //weight: 1
        $x_1_6 = "mesujozibuzerakatubukulixubifi" ascii //weight: 1
        $x_1_7 = "narinogiyudarotefilawazutupa" ascii //weight: 1
        $x_1_8 = "digetekugabigutural cozedacumopecibocetohijefebofe dudisinadeyuzilogokod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PrivateLoader_LMAA_2147908638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PrivateLoader.LMAA!MTB"
        threat_id = "2147908638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://dsepc5ud74wta.cloudfront.net/load/load.php" wide //weight: 2
        $x_2_2 = "://representativestem.xyz/ir/sreb.php" wide //weight: 2
        $x_1_3 = "/silent" wide //weight: 1
        $x_1_4 = "/weaksecurity" wide //weight: 1
        $x_1_5 = "/nocookies" wide //weight: 1
        $x_1_6 = "/username" wide //weight: 1
        $x_1_7 = "/popup" wide //weight: 1
        $x_1_8 = "/resume" wide //weight: 1
        $x_1_9 = "/useragent" wide //weight: 1
        $x_1_10 = "/connecttimeout" wide //weight: 1
        $x_1_11 = "/header" wide //weight: 1
        $x_1_12 = "/tostackconv" wide //weight: 1
        $x_1_13 = "/tostack" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_2_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PrivateLoader_AMMF_2147909498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PrivateLoader.AMMF!MTB"
        threat_id = "2147909498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-30] 20 00 28 00 20 00 22 00 78 00 72 00 65 00 61 00 72 00 79 00 33 00 32 00 22 00 20 00 29 00 20 00 2c 00 20 00 [0-30] 20 00 28 00 20 00 22 00 63 00 67 00 65 00 22 00 20 00 29 00 20 00 2c 00 20 00 [0-30] 20 00 28 00 20 00 22 00 49 00 76 00 65 00 67 00 68 00 6e 00 79 00 4e 00 79 00 79 00 62 00 70 00 22 00 20 00 29 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-30] 20 28 20 22 78 72 65 61 72 79 33 32 22 20 29 20 2c 20 [0-30] 20 28 20 22 63 67 65 22 20 29 20 2c 20 [0-30] 20 28 20 22 49 76 65 67 68 6e 79 4e 79 79 62 70 22 20 29 20}  //weight: 1, accuracy: Low
        $x_1_3 = {43 00 48 00 52 00 20 00 28 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 24 00 [0-30] 20 00 2b 00 20 00 2d 00 36 00 35 00 20 00 2b 00 20 00 31 00 33 00 20 00 2c 00 20 00 32 00 36 00 20 00 29 00 20 00 2b 00 20 00 36 00 35 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {43 48 52 20 28 20 4d 4f 44 20 28 20 24 [0-30] 20 2b 20 2d 36 35 20 2b 20 31 33 20 2c 20 32 36 20 29 20 2b 20 36 35 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {43 00 48 00 52 00 20 00 28 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 24 00 [0-30] 20 00 2b 00 20 00 2d 00 39 00 37 00 20 00 2b 00 20 00 31 00 33 00 20 00 2c 00 20 00 32 00 36 00 20 00 29 00 20 00 2b 00 20 00 39 00 37 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {43 48 52 20 28 20 4d 4f 44 20 28 20 24 [0-30] 20 2b 20 2d 39 37 20 2b 20 31 33 20 2c 20 32 36 20 29 20 2b 20 39 37 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

