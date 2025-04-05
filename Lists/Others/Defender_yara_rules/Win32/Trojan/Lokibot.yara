rule Trojan_Win32_Lokibot_2147729246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot!MTB"
        threat_id = "2147729246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 62 de 49 84 f6 49 38 f6 49 66 39 c1 49 0f 71 f5 ?? 8b 1c 0f 66 0f 66 e9 f6 c4 ?? 53 66 81 fe ?? ?? 3d ?? ?? ?? ?? 38 f6 39 c9 66 85 c9 31 34 24 38 db f7 c3 ?? ?? ?? ?? 38 c8 85 d0 0f 75 c8 0f e2 c4 66 f7 c1 ?? ?? 85 d8 66 0f 73 f3 ?? 66 85 d2 8f 04 08 38 e5 84 c3 38 d0 83 f9 ?? 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_K_2147730516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.K!MTB"
        threat_id = "2147730516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 fc b9 ?? ?? ?? ?? 89 c7 [0-42] f3 a4 [0-42] bb ?? ?? ?? ?? 31 1c 08 83 c1 03 41 81 f9 ?? ?? ?? ?? 75 f1 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_A_2147731203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.A!MTB"
        threat_id = "2147731203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 45 f8 43 81 7d f8 30 00 8a 03 34 ?? 88 07 [0-16] 8a 07 e8 ?? ?? ?? ?? [0-16] 83 06 01 73 ?? e8 ?? ?? ?? ?? [0-16] ff 45 f8 43 81 7d f8 ?? ?? ?? ?? 75 ?? [0-16] 8b 4d fc [0-16] 81 c1 ?? ?? ?? ?? [0-16] ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SF_2147731654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SF!MTB"
        threat_id = "2147731654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 5f 5e c3 [0-16] 80 f2 cd 88 10 [0-16] c3}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 01 00 00 00 [0-16] 8b c8 03 cb 73 ?? e8 ?? ?? ?? ?? [0-16] c6 01 ?? [0-16] 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SF_2147731654_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SF!MTB"
        threat_id = "2147731654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec eb ?? [0-5] 8a 45 08 [0-5] 30 01 [0-5] eb ?? [0-5] [0-5] 8b 4d 0c eb ?? 5d c2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 06 03 c3 50 68 ?? 00 00 00 ff 15 ?? ?? ?? ?? ff 06 81 3e ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SG_2147731655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SG!MTB"
        threat_id = "2147731655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 03 55 f8 [0-10] 8a 03 [0-10] 34 ?? [0-10] 88 02 [0-10] 8d 45 f8 e8 ?? ?? ?? ?? [0-10] 43 4e 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SG_2147731655_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SG!MTB"
        threat_id = "2147731655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 e8 53 56 57 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 e8 44 0e f9 ff 89 45 fc [0-5] 8b 45 fc 89 45 f8 [0-4] 8d 45 e8 50 e8 [0-16] 8b 45 f8 3b 45 fc 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d3 8b c6 e8 ?? ?? ff ff 46 81 fe ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 55 e8 8d 45 f0 e8 ?? ?? ff ff 8b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SH_2147731697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SH!MTB"
        threat_id = "2147731697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 13 b0 86 02 cb c0 c9 03 f6 d9 c0 c9 03 f6 d1 32 cb f6 d1 80 e9 03 80 f1 8a c0 c1 02 80 f1 33 f6 d1 80 e9 39 d0 c1 2a cb 32 cb 80 c1 59 f6 d1 2a cb 32 cb f6 d9 80 f1 b7 2a c1 f6 d0 2c 55 f6 d0 2c 5e 34 88 2a c3 34 9b 02 c3 c0 c8 03 02 c3 88 04 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SH_2147731697_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SH!MTB"
        threat_id = "2147731697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {55 8b ec eb ?? [0-16] 8a 45 08 [0-16] 30 01 [0-16] eb ?? [0-16] 8b 4d 0c [0-16] eb ?? [0-16] 5d c2}  //weight: 3, accuracy: Low
        $x_1_2 = {8b ca 03 cb c6 01 ?? [0-16] 43 48 75 ?? 33 c0 5b c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b da 03 d9 [0-16] c6 03 ?? 41 48 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_SH_2147731697_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SH!MTB"
        threat_id = "2147731697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 e4 53 56 57 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 e8 ?? ?? ?? ?? 89 45 fc [0-16] 8b 45 fc 89 45 f8 [0-16] 8d 45 e8 50 e8 [0-16] 8b 45 f8 3b 45 fc 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 b2 9c 8b c3 e8 ?? ?? ff ff [0-10] 46 81 fe ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 55 e8 8d 45 f0 e8 ?? ?? ff ff 8b c8}  //weight: 1, accuracy: Low
        $x_1_4 = "Resolving hostname %s" ascii //weight: 1
        $x_1_5 = "Disconnecting from %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SJ_2147731727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SJ!MTB"
        threat_id = "2147731727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {53 56 51 8b d8 8b f4 [0-16] 56 6a 40 52 53 e8 ?? ?? ?? ?? [0-16] 33 c0 89 06 [0-16] 8b 06 03 c3 73 05 e8 ?? ?? ?? ?? 50 [0-6] ff 15 ?? ?? ?? ?? [0-16] ff 06 81 3e ?? ?? ?? ?? 75}  //weight: 3, accuracy: Low
        $x_1_2 = {8b 55 0c eb ?? [0-16] 5d c2 60 00 55 8b ec [0-16] eb ?? [0-16] 8a 45 08 [0-16] 30 02 [0-16] eb ?? [0-16] 8b 55 0c eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d 0c eb ?? [0-16] 5d c2 60 00 55 8b ec [0-16] eb ?? [0-16] 8a 45 08 [0-16] 30 01 [0-16] eb ?? [0-16] 8b 4d 0c eb}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 08 8a 10 80 f2 ?? [0-16] 88 10 5d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_SK_2147731733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SK!MTB"
        threat_id = "2147731733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 06 8b 06 [0-16] 8d 90 ?? ?? ?? ?? 8a 12 80 f2 ?? 03 c3 88 10 ff 06 81 3e ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 01 00 00 00 [0-16] 8b cb 03 c8 c6 01 ?? [0-16] 43 4a 75 ?? 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SL_2147731798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SL!MTB"
        threat_id = "2147731798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {53 56 51 8b d8 8b f4 [0-16] 56 6a 40 52 53 e8 ?? ?? ?? ?? [0-16] 33 c0 89 06 [0-16] 8b 06 03 c3 73 05 e8 ?? ?? ?? ?? 50 [0-6] ff 15 ?? ?? ?? ?? [0-16] ff 06 81 3e ?? ?? ?? ?? 75}  //weight: 3, accuracy: Low
        $x_1_2 = {55 8b ec eb ?? [0-16] 8a 45 08 30 ?? eb ?? [0-16] 8b 7d 0c [0-16] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SN_2147731887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SN!MTB"
        threat_id = "2147731887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 88 45 fb [0-4] 8a 45 fb 32 45 fa 8b 55 fc 88 02 ff 45 f4 81 7d f4}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 e0 01 00 00 00 6a 00 6a 00 e8 ?? ?? ?? ?? ff 45 e0 81 7d e0 ?? ?? ?? ?? 75 ?? 89 ff 89 ff 89 ff e8 ?? ?? ?? ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SN_2147731887_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SN!MTB"
        threat_id = "2147731887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 55 f8 03 55 f4 [0-16] 8a 03 [0-16] 34 ?? [0-16] 88 02 [0-16] 8d 45 f4 e8 ?? ?? ?? ?? [0-16] 43 4e 75}  //weight: 3, accuracy: Low
        $x_3_2 = {8b 45 f8 03 45 f4 [0-16] 8a 13 [0-16] 80 f2 ?? [0-16] 88 10 [0-16] 8d 45 f4 e8 ?? ?? ?? ?? [0-16] 43 4e 75}  //weight: 3, accuracy: Low
        $x_1_3 = {8b c2 03 c3 [0-16] c6 00 ?? [0-16] 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_SO_2147731888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SO!MTB"
        threat_id = "2147731888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5d c2 08 00 50 00 55 8b ec [0-16] eb ?? [0-16] 8a 45 08 [0-16] 30 ?? [0-16] eb ?? [0-16] 8b ?? 0c [0-16] eb ?? [0-16] 5d c2 08 00}  //weight: 3, accuracy: Low
        $x_1_2 = {8b ca 03 cb [0-16] c6 01 ?? [0-16] 43 48 75}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 01 00 00 00 [0-16] 8b da 03 d9 c6 03 ?? [0-16] 41 48 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_SP_2147733232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SP!MTB"
        threat_id = "2147733232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d c2 08 00 50 00 55 8b ec [0-16] eb ?? [0-16] 8a 45 08 [0-16] 30 ?? [0-16] eb ?? [0-16] 8b ?? 0c [0-16] eb ?? [0-16] 5d c2 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SQ_2147733254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SQ!MTB"
        threat_id = "2147733254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 68 ?? ?? 00 00 6a 00 e8 ?? ?? ?? ?? [0-5] [0-16] 33 c0 89 ?? ?? be ?? ?? ?? ?? bb ?? ?? ?? ?? [0-16] 8b [0-3] 03 ?? ?? [0-16] 8a ?? [0-16] (34|80) [0-2] [0-16] 88 ?? ?? [0-16] 8a ?? ?? [0-16] 88 ?? [0-16] [0-4] e8 ?? ?? ?? ?? [0-16] 8b ?? [0-16] 05 ?? ?? ?? ?? [0-16] 89 ?? ?? [0-16] 43 4e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_ST_2147733276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.ST!MTB"
        threat_id = "2147733276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 c7 00 8b 4d fc 03 cf 83 c7 00 8a 10 83 c7 00 83 c7 00 32 55 fa 88 11 83 c7 00 83 c7 00 83 c7 00 83 c7 00 8a 55 fb 30 11 83 c7 00 47 40 4e 75 cf}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_ST_2147733276_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.ST!MTB"
        threat_id = "2147733276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "myneho.com" wide //weight: 1
        $x_1_2 = "QupZilla\\profiles\\default\\browsedata.db" ascii //weight: 1
        $x_1_3 = "/group/one/two/three/four/five/fre.php" ascii //weight: 1
        $x_1_4 = "\\Microsoft\\Windows\\Explorerorer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_TS_2147733278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.TS!MTB"
        threat_id = "2147733278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 4d 0c [0-16] 8a 45 08 [0-16] 30 ?? [0-16] 5d c2}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 5e 5b c3 70 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? [0-16] 83 fb ?? [0-16] 7e ?? [0-16] c7 05 ?? ?? ?? ?? ?? ?? ?? ?? [0-16] [0-2] e8 ?? ?? ?? ?? [0-16] eb ?? [0-16] 4e 75 ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 5f 5e 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SW_2147733543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SW!MTB"
        threat_id = "2147733543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 [0-16] 8b c2 03 c3 [0-16] c6 00 ?? [0-16] 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 34 24 03 f7 [0-16] 8a 08 [0-16] 80 f1 ?? [0-16] 88 0e [0-16] 47 [0-16] 40 4a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_YA_2147735017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.YA!MTB"
        threat_id = "2147735017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 f8 d0 f9 ff 90 33 c0 90 90 33 db 90 c6 44 ?? ?? ?? 8b d3 8b fe 03 fa 90 8a 90 ?? ?? ?? 00 32 54 ?? ?? 88 17 40 90 40 90 43 81 ?? ?? ?? 00 00 75 da 90 90 8b c6 e8 12 ff ff ff 90 90 59 5a 5f 5e 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SX_2147735686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SX!MTB"
        threat_id = "2147735686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 8b c1 23 c6 8a 44 05 f4 30 81 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? ?? 72 e9 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? b8 ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SY_2147735874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SY!MTB"
        threat_id = "2147735874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec ff 75 0c [0-16] 8a 45 08 [0-16] 5f [0-16] 30 07 5d c2 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 01 00 00 00 8b ca 03 cb c6 01 14 43 48 75 f5 33 c0 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_C_2147739770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.C!MTB"
        threat_id = "2147739770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Borland" ascii //weight: 1
        $x_1_2 = {6a 00 6a 00 e8 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 90 90 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 90 a1 ?? ?? ?? ?? 40 83 e0 07 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 88 02 90 ff 05 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 90 68 00 80 00 00 6a 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_C_2147739770_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.C!MTB"
        threat_id = "2147739770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Borland\\Delphi\\" ascii //weight: 1
        $x_1_2 = {64 ff 30 64 89 20 83 2d ?? ?? ?? 00 01 0f 83 ?? ?? 00 00 [0-64] 68 ?? ?? ?? 00 64 ff 30 64 89 20}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 08 03 45 f4 73 [0-16] 8a 00 88 45 fb 8a 45 fb 34 ?? 8b 55 08 03 55 f4 73 [0-16] 88 02 ff 45 f4 81 7d f4 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 08 03 45 f4 8a 00 88 45 fb 8a 45 fb 34 ?? 8b 55 08 03 55 f4 88 02 ff 45 f4 81 7d f4 ?? ?? ?? ?? 75 dc ff 65 08}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 45 08 03 45 f8 73 [0-16] c6 45 ff [0-32] 8a 00 88 45 f7 ?? 8a 45 f7 32 45 ff 8b 55 ec 88 02 ff 45 f8 81 7d f8 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 45 08 03 45 f4 8a 00 88 45 f3 [0-16] 8a 45 f3 32 45 fb 8b 55 fc 88 02 ff 45 f4 81 7d f4 ?? ?? ?? ?? 75 ?? ff 65 08 3f 00 c6 45 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Lokibot_D_2147739771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.D!MTB"
        threat_id = "2147739771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 90 90 [0-16] 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {4b 75 f8 e8 ?? ?? ?? ?? 90 90 bb ?? ?? ?? 00 e8 ?? ?? ?? ?? 4b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_D_2147739771_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.D!MTB"
        threat_id = "2147739771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 5a 5f 5e 5b c3 4f 00 b0 ?? 8b d3 8b fe 03 fa 8b 15 ?? ?? ?? ?? 8a 92 ?? ?? ?? ?? 32 d0 88 17 83 05 ?? ?? ?? ?? 02 43 81 fb ?? ?? 00 00 75 d8 8b c6 e8 ?? ?? ff ff 5a 5f 5e 5b c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f0 54 6a 40 68 83 5b 00 00 56 e8 ?? ?? ?? ?? 33 c0 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SZ_2147739787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SZ!MTB"
        threat_id = "2147739787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 54 6a 40 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? [0-16] 33 c0 a3 ?? ?? ?? ?? [0-16] 33 db [0-16] b2 ?? 8b c3 8b fe 03 f8 a1 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? [0-16] 32 c2 88 07}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 01 00 00 00 8b da 03 d9 c6 03 ?? 41 48 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_DB_2147739927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.DB!MTB"
        threat_id = "2147739927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 03 c3 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 34 b1 a2 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 88 10 83 05 e4 1b 47 00 02 90 43 81 fb 4d 5e 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {bb ba 8a 02 00 6a 00 e8 ?? ?? ?? ?? 90 4b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_B_2147740676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.B!MTB"
        threat_id = "2147740676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 8d 84 24 ?? ?? ?? ?? 33 ff 0f 57 c0 50 8d 5f 0a 89 74 24 ?? 89 74 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_B_2147740676_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.B!MTB"
        threat_id = "2147740676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 30 64 89 20 83 2d ?? ?? ?? 00 01 0f 83 ?? ?? 00 00 68 ff 00 00 00 68 ?? ?? ?? 00 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 03 c7 [0-16] a3 ?? ?? ?? 00 [0-16] 88 15 ?? ?? ?? 00 [0-16] 8b 15 ?? ?? ?? 00 [0-16] a0 ?? ?? ?? 00 [0-16] 89 d1 [0-16] 88 01 [0-16] 47 [0-16] 81 ff ?? ?? 00 00 75 60 00 8a 90 ?? ?? ?? 00 [0-16] 32 d3 [0-16] 8b c6 03 c7}  //weight: 1, accuracy: Low
        $x_1_3 = {8b f7 03 f3 [0-16] a2 ?? ?? ?? 00 [0-16] 8b c6 e8 ?? ?? ff ff [0-16] 43 [0-16] 81 fb ?? ?? 00 00 75 60 00 8a 80 ?? ?? ?? 00 [0-16] 34 e0 [0-16] 8b f7 03 f3}  //weight: 1, accuracy: Low
        $x_1_4 = {8b c7 03 c3 [0-16] 8b f0 [0-16] 88 15 ?? ?? ?? 00 [0-16] 8b c6 e8 ?? ?? ff ff [0-16] 43 [0-16] 81 fb ?? ?? 00 00 75 50 00 8a 90 ?? ?? ?? 00 [0-16] 80 f2 ?? [0-16] 8b c7 03 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {8b c6 03 c1 [0-16] 89 45 fc [0-16] 88 55 fb [0-16] 8b 55 fc [0-16] 8a 45 fb [0-16] 88 02 [0-16] 41 [0-16] 81 f9 ?? ?? 00 00 75 60 00 8a 90 ?? ?? ?? 00 [0-16] 80 f2 f9 [0-16] 8b c6 03 c1}  //weight: 1, accuracy: Low
        $x_1_6 = {8b cb 03 c8 [0-16] 88 11 [0-16] 40 [0-16] 3d ?? ?? 00 00 75 40 00 8a 91 ?? ?? ?? 00 [0-16] 80 f2 c3 [0-16] 8b cb 03 c8}  //weight: 1, accuracy: Low
        $x_1_7 = {8b c7 03 c3 [0-16] 8b f0 [0-16] 8b c2 [0-16] a2 ?? ?? ?? 00 [0-16] 8b c6 e8 ?? ?? ff ff [0-16] 43 [0-16] 81 fb ?? ?? 00 00 75 50 00 8a 90 ?? ?? ?? 00 [0-16] 80 f2 ?? [0-16] 8b c7 03 c3}  //weight: 1, accuracy: Low
        $x_1_8 = {03 ef 73 05 e8 ?? ?? ?? ?? [0-16] 8b c5 [0-16] e8 ?? ?? ?? ?? [0-16] 43 [0-16] 81 fb ?? ?? 00 00 75 50 00 8a 97 ?? ?? ?? 00 [0-16] 32 d0 [0-16] 8b fb [0-16] 8b ee [0-16] 03 ef 73 05 e8}  //weight: 1, accuracy: Low
        $x_1_9 = {8b d6 03 d0 [0-16] 88 0a [0-16] 40 [0-16] 3d ?? ?? 00 00 75 40 00 8b d0 [0-16] 8a 8a ?? ?? ?? 00 [0-16] 80 f1 ?? [0-16] 8b d6 03 d0}  //weight: 1, accuracy: Low
        $x_1_10 = {8b d0 8b ce [0-16] a0 ?? ?? ?? 00 [0-16] e8 ?? ?? ?? ?? [0-16] 43 [0-16] 81 fb ?? ?? 00 00 75 50 00 8b c3 [0-16] 8a 80 ?? ?? ?? 00 [0-16] 32 05 ?? ?? ?? 00 [0-16] a2 ?? ?? ?? 00 [0-16] a1 ?? ?? ?? 00 [0-16] 03 c3 [0-16] 8b f0 [0-16] e8 ?? ?? ?? ?? [0-16] 8b d0 8b ce}  //weight: 1, accuracy: Low
        $x_1_11 = {ff ff ff 43 81 fb 80 00 c6 05 ?? ?? ?? 00 ?? [0-16] 8b c3 [0-16] 8a 80 ?? ?? ?? 00 [0-16] 8a 15 ?? ?? ?? 00 [0-16] 32 d0 [0-16] 8b cb [0-16] 8b c6 [0-16] 03 c1 [0-16] e8 ?? ff ff ff 43 81 fb ?? ?? 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Lokibot_SA_2147741252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SA!MSR"
        threat_id = "2147741252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 61 00 6d 00 61 00 7a 00 6f 00 6e 00 2e 00 63 00 4f 00 4d}  //weight: 1, accuracy: High
        $x_1_2 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 42 00 49 00 54 00 54 00 45 00 52 00 45 00 4e}  //weight: 1, accuracy: High
        $x_1_3 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 79 00 72 00 6d 00 65 00 63 00 6f 00 63 00 68 00 6f 00 72 00 79}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 72 00 67 00 6d 00 6f 00 64 00 69 00 67 00 65 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Lokibot_BC_2147741472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.BC!MTB"
        threat_id = "2147741472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 04 00 00 00 f7 f1 8b ?? ?? 0f be ?? ?? 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d f8 88 81 03 8b 55 ?? 83 c2 01 89 55 ?? 81 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_BC_2147741472_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.BC!MTB"
        threat_id = "2147741472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 c9 eb 01 [0-16] 43 eb [0-16] 0b 0f eb [0-16] 31 d9 eb [0-16] 39 c1 75 ?? eb [0-16] eb [0-16] 89 de eb [0-16] eb [0-16] b9 ?? ?? ?? ?? eb [0-16] eb [0-16] 81 f1 ?? ?? ?? ?? eb [0-16] eb [0-16] 81 f1 ?? ?? ?? ?? eb [0-16] eb [0-16] 81 c1 ?? ?? ?? ?? eb 82 eb 35 eb dd eb 6e 29 d2 eb 31 eb d5 03 11 eb e2 eb 3d bb fd d2 5e 00 eb ca eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_XD_2147741767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.XD!MTB"
        threat_id = "2147741767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 [0-16] 8b c2 03 c3 [0-16] c6 00 ?? [0-16] 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 83 c4 [0-40] 8a 92 b8 eb 44 00 80 f2 e8 88 10 [0-8] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_TW_2147741801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.TW!MTB"
        threat_id = "2147741801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 [0-16] 8b c2 03 c3 [0-16] c6 00 ?? [0-16] 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 10 5f 5e c3 8d 40 00 90 [0-16] 80 f2 ?? 88 10 90 [0-16] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_XS_2147742176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.XS!MTB"
        threat_id = "2147742176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 [0-16] 8b c2 03 c3 [0-16] c6 00 ?? [0-16] 43 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 53 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 83 2d ?? ?? ?? ?? 01 0f ?? ?? ?? ?? 00 68 ?? ?? 00 00 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_R_2147743149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.R"
        threat_id = "2147743149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 80 f1 ?? 88 0b 42 40 81 fa 7c 5c 00 00 75 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_CY_2147744167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.CY!MTB"
        threat_id = "2147744167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 f8 89 55 f8 89 45 fc 90 [0-16] 8b ?? fc ff 75 f8 01 ?? 24 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {fa ff 8b d8 90 [0-16] 85 db 74 ?? 90 [0-16] [0-8] 90 [0-16] ba ?? ?? ?? ?? 8b c3 e8 ?? ?? fa ff 90 [0-16] 8b c3 e8 ?? ?? fa ff 90 [0-21] [0-6] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AZ_2147744168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AZ!MTB"
        threat_id = "2147744168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ce c1 e1 05 8b fe c1 ef 02 03 cf 0f be 3a 03 cf 33 f1 42 48 e9 38 26 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {56 8b f1 85 f6 0f 84 1e 00 00 00 33 c9 41 2b c8 57 8b 7c 24 0c 8d 14 01 83 e2 0f 8a 14 3a 30 10 40 4e 0f 85 e9 ff ff ff 5f 5e c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AZ_2147744168_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AZ!MTB"
        threat_id = "2147744168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 29 c9 eb 06 [0-16] 85 c0 eb [0-16] 43 eb [0-16] 66 81 fa ?? ?? eb [0-16] 0b 0f eb [0-16] 66 81 fb ?? ?? eb [0-16] 31 d9 eb [0-16] 85 c0 eb [0-16] 39 c1 eb [0-16] 75 9c 66 81 fa ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {29 c9 eb 01 [0-16] 43 eb [0-16] 0b 0f eb [0-16] 31 d9 eb [0-16] 39 c1 75 ?? eb [0-16] eb [0-16] 89 de eb [0-16] eb [0-16] 48 b9 ?? ?? ?? 00 eb [0-16] eb [0-16] 81 f1 ?? ?? ?? 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Lokibot_BY_2147744262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.BY!MTB"
        threat_id = "2147744262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 f8 89 55 f8 89 45 fc 90 [0-16] 8b 5d fc ff 75 f8 01 1c 24 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f8 89 45 f0 90 [0-16] 68 ?? 00 00 00 e8 df 4b fa ff 90 [0-16] 83 fb ?? 76 ?? 90 [0-16] e8 de 4a fa ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_CQ_2147744482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.CQ!MTB"
        threat_id = "2147744482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 83 c1 01 89 4d fc 81 7d fc ?? ?? 00 00 73 ?? 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b [0-6] 0f be 0c 10 8b 55 fc 0f b6 ?? ?? ?? ?? ?? ?? 33 c1 8b 4d fc 88 [0-6] eb}  //weight: 1, accuracy: Low
        $x_1_2 = {52 6a 40 68 ?? ?? 00 00 [0-8] ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? 6a ?? 6a ?? 68 ?? ?? ?? ?? [0-6] ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_PA_2147744686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.PA!MTB"
        threat_id = "2147744686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 45 08 03 45 ?? 73 05 e8 ?? ?? ?? ?? 8a 00 88 45 ?? 8a 45 ?? 34 ?? 8b 55 08 03 55 ?? 73 05 e8 ?? ?? ?? ?? 88 02 ff 45 ?? 81 7d ?? ?? ?? 02 00 75 ce ff 65 08}  //weight: 20, accuracy: Low
        $x_1_2 = {50 6a 40 68 ?? ?? 02 00 8b 45 08 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_PB_2147744694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.PB!MTB"
        threat_id = "2147744694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 45 fc e8 ?? ?? ?? ?? 8b 55 fc 0f b6 54 3a ff 33 c2 50 8b 45 f8 e8 ?? ?? ?? ?? 8b 55 f8 0f b6 54 1a ff 33 c2 5a 33 d0 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? 43 8b 45 f8 e8 ?? ?? ?? ?? 3b d8 7e 05 bb 01 00 00 00 47 4e 75}  //weight: 20, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_FW_2147745031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.FW!MTB"
        threat_id = "2147745031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 04 ba ?? ?? ?? ?? 56 2b d1 be ?? ?? 00 00 8a 04 0a 34 ?? 88 01 41 4e 75 f5 b8 ?? ?? 00 00 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_JJS_2147745414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.JJS!MTB"
        threat_id = "2147745414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 db b0 6e 8b d3 ?? 00 03 d6 89 14 24 8a 97 ?? ?? ?? ?? 90 32 d0 8b 04 24 88 10}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_E_2147745438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.E!MTB"
        threat_id = "2147745438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 03 55 f8 b0 ?? e8 ?? ?? ff ff ff 45 f8 81 7d f8 ?? ?? ?? ?? 75 e7 ff 65 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 06 03 c3 73 05 e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? 00 ff 06 81 3e ?? ?? 00 00 75 df}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d 08 03 4d fc b2 ?? 8b 45 fc e8 ?? ?? ff ff ff 45 fc 81 7d fc ?? ?? ?? ?? 75 e4 ff 65 08}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 45 f8 81 7d f8 1f 00 b1 ?? 8b 55 f8 8b 45 08 e8 ?? ?? ?? ?? ff 45 f8 81 7d f8 ?? ?? 00 00 75 e7 ff 65 08}  //weight: 1, accuracy: Low
        $x_1_5 = {55 8b ec 83 c4 f8 89 55 f8 88 45 ff 8b 45 f8 8a 55 ff 30 10 59 59 5d c3}  //weight: 1, accuracy: High
        $x_1_6 = {55 8b ec ff 75 0c 90 8a 45 08 5a 30 02 90 90 5d c2 08 00}  //weight: 1, accuracy: High
        $x_1_7 = {55 8b ec 83 c4 f0 89 4d f4 88 55 fb 89 45 fc 8b 45 f4 89 45 fc 8a 45 fb 88 45 f3 8b 45 fc 8a 00 88 45 f2 8a 45 f2 32 45 f3 8b 55 fc 88 02 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_8 = {55 8b ec 83 c4 f0 88 4d f7 89 55 f8 89 45 fc 8b 45 fc 03 45 f8 89 45 f0 8b 45 f0 8a 00 88 45 f6 8a 45 f6 32 45 f7 8b 55 f0 88 02 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_9 = {55 8b ec 83 c4 ec 88 4d f7 89 55 f8 89 45 fc 8b 45 fc 03 45 f8 89 45 f0 8b 45 f0 8a 00 88 45 f6 8b 45 f0 89 45 ec 8a 45 f6 30 45 f7 8b 45 ec 8a 55 f7 88 10 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_10 = {64 ff 30 64 89 20 83 2d ?? ?? ?? 00 01 0f 83 ?? ?? 00 00 [0-79] 68 ?? ?? ?? 00 64 ff 30 64 89 20}  //weight: 1, accuracy: Low
        $x_1_11 = {64 ff 30 64 89 20 ff 05 ?? ?? ?? 00 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Lokibot_SE_2147745464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SE!MTB"
        threat_id = "2147745464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\DownloadManager\\Passwords" ascii //weight: 1
        $x_1_2 = "get_Password" ascii //weight: 1
        $x_1_3 = "Windows Domain Password Credential" ascii //weight: 1
        $x_1_4 = "DecryptIePassword" ascii //weight: 1
        $x_1_5 = "enablePasswordRetrieval" ascii //weight: 1
        $x_1_6 = "\\Ftplist.txt" ascii //weight: 1
        $x_1_7 = "\\AppData\\Roaming\\The Bat!" ascii //weight: 1
        $x_1_8 = "checkip.amazonaws.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Lokibot_JRL_2147745531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.JRL!MTB"
        threat_id = "2147745531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b fe 03 f8 90 90 8b c2 8a 80 ?? ?? ?? ?? 90 90 32 44 24 04 88 07 37 00 33 d2 90 90 33 db 90 c6 44 24 ?? ?? 8b c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_GJ_2147746098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.GJ!MTB"
        threat_id = "2147746098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e9 b0 1f 00 00 55 8b ec 81 ec e0 00 00 00 56 57 b8 6b 00 00 00 66 89 45 dc b9 65 00 00 00 66 89 4d de ba 72 00 00 00 66 89 55 e0 b8 6e 00 00 00 66 89 45 e2 b9 65 00 00 00 66 89 4d e4 ba 6c 00 00 00 66 89 55 e6 b8 33 00 00 00 66 89 45 e8 b9 32 00 00 00 66 89 4d ea ba 2e 00 00 00 66 89 55 ec b8 64 00 00 00 66 89 45 ee b9 6c 00 00 00 66 89 4d f0 ba 6c 00 00 00 66 89 55 f2 33 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_BD_2147746108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.BD!MTB"
        threat_id = "2147746108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 74 74 70 3a 2f 2f [0-21] 2f 6d 65 78 69 69 69 2f 50 61 6e 65 6c 2f 66 69 76 65}  //weight: 5, accuracy: Low
        $x_5_2 = "/fre.php" ascii //weight: 5
        $x_1_3 = {43 3a 5c 55 73 65 72 73 5c [0-21] 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c [0-16] 5c [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {43 3a 5c 55 73 65 72 73 5c [0-21] 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c [0-16] 5c [0-16] 2e 6c 63 6b}  //weight: 1, accuracy: Low
        $x_1_5 = {43 3a 5c 55 73 65 72 73 5c [0-21] 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c [0-16] 5c [0-16] 2e 68 64 62}  //weight: 1, accuracy: Low
        $x_3_6 = "@%SystemRoot%\\system32\\windows.storage.dll" ascii //weight: 3
        $x_3_7 = "protected_storage" ascii //weight: 3
        $x_1_8 = {6e 63 61 6c 72 70 63 3a 5b [0-21] 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_SD_2147746112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SD!!Lokibot.gen!SD"
        threat_id = "2147746112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "Lokibot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "SD: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 74 74 70 3a 2f 2f [0-21] 2f 6d 65 78 69 69 69 2f 50 61 6e 65 6c 2f 66 69 76 65}  //weight: 5, accuracy: Low
        $x_5_2 = "/fre.php" ascii //weight: 5
        $x_1_3 = {43 3a 5c 55 73 65 72 73 5c [0-21] 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c [0-16] 5c [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {43 3a 5c 55 73 65 72 73 5c [0-21] 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c [0-16] 5c [0-16] 2e 6c 63 6b}  //weight: 1, accuracy: Low
        $x_1_5 = {43 3a 5c 55 73 65 72 73 5c [0-21] 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c [0-16] 5c [0-16] 2e 68 64 62}  //weight: 1, accuracy: Low
        $x_3_6 = "@%SystemRoot%\\system32\\windows.storage.dll" ascii //weight: 3
        $x_3_7 = "protected_storage" ascii //weight: 3
        $x_1_8 = {6e 63 61 6c 72 70 63 3a 5b [0-21] 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_JDJ_2147746241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.JDJ!MTB"
        threat_id = "2147746241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c0 33 db ?? 00 8b d3 8a 88 ?? ?? ?? ?? 88 4d fb 8a 4d fb 80 f1 62 03 d6 88 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SE_2147747903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SE!!Lokibot.gen!SD"
        threat_id = "2147747903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "Lokibot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "SD: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\DownloadManager\\Passwords" ascii //weight: 1
        $x_1_2 = "get_Password" ascii //weight: 1
        $x_1_3 = "Windows Domain Password Credential" ascii //weight: 1
        $x_1_4 = "DecryptIePassword" ascii //weight: 1
        $x_1_5 = "enablePasswordRetrieval" ascii //weight: 1
        $x_1_6 = "\\Ftplist.txt" ascii //weight: 1
        $x_1_7 = "\\AppData\\Roaming\\The Bat!" ascii //weight: 1
        $x_1_8 = "checkip.amazonaws.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Lokibot_V_2147749756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.V!MTB"
        threat_id = "2147749756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 03 e8 8d 56 ?? 8b c3 e8 ?? ?? ?? ?? 89 43 01 8b 07 89 43 05 89 1f 83 c3 ?? 8b c3 2b c6 3d ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_2_2 = {8b 55 08 03 d0 80 32 c1 40 3d ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SS_2147749972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SS!eml"
        threat_id = "2147749972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 05 00 00 00 8b 55 08 03 d0 73 05 e8 [0-4] 80 32 4b 40 3d 00 5c 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SK_2147749973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SK!eml"
        threat_id = "2147749973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8b d3 03 d0 73 05 e8 ?? ?? ?? ?? 80 32 3b 40 3d 7a 5b 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 8b d3 03 d0 73 05 e8 ?? ?? ?? ?? 80 32 12 40 3d 48 5c 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Lokibot_SMC_2147750206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SMC!MTB"
        threat_id = "2147750206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Borland\\Delphi" ascii //weight: 1
        $x_3_2 = {88 0a 83 c0 20 00 8a 90 ?? ?? ?? 00 80 f2 ?? 88 15 ?? ?? ?? ?? 8b 15 ?? 04 8a 0d ?? 04}  //weight: 3, accuracy: Low
        $x_1_3 = {83 f8 07 75 ?? 6a 01 e8 ?? ?? ?? ?? 25 00 ff 00 00 3d 00 0d 00 00 74 ?? 3d 00 04 00 00 75 37 00 6a 00 e8 ?? 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_F_2147750330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.F!MTB"
        threat_id = "2147750330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 03 d3 73 [0-32] 8a 12 80 f2 ?? 8b 4d fc 03 c8 73 [0-32] 88 11 ff 45 fc 81 7d fc ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c0 6a 00 e8 ?? ?? ?? ?? c3 53 33 c9 8b d9 03 d8 73 05 e8 ?? ?? ?? ?? 30 13 41 81 f9 ?? ?? 00 00 75 ea 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Lokibot_PA_2147750815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.PA!!Lokibot.gen!SD"
        threat_id = "2147750815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "Lokibot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "SD: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/fre.php" ascii //weight: 3
        $x_1_2 = "%s\\Cyberduck" ascii //weight: 1
        $x_1_3 = "\\QupZilla\\profiles\\default\\browsedata.db" ascii //weight: 1
        $x_1_4 = "%s\\%s\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_5 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins" ascii //weight: 1
        $x_1_6 = "%s\\Thunderbird\\profiles.ini" ascii //weight: 1
        $x_1_7 = "%s\\FossaMail\\profiles.ini" ascii //weight: 1
        $x_1_8 = "%s\\Foxmail\\mail" ascii //weight: 1
        $x_1_9 = "%s\\NETGATE\\Black Hawk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_G_2147751609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.G!MTB"
        threat_id = "2147751609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 f4 53 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 53 56 57 6a 40 68 00 30 00 00 68 ?? ?? 00 00 6a 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_5_3 = {8a 01 88 45 fb 8b 55 fc 8a 45 fb 88 02 b0 ad 30 02 ff 45 fc ff 45 f4 41 81 7d f4 ?? ?? 00 00 75 df 81 c3 ?? ?? 00 00 89 5d f4 ff 75 f4 c3}  //weight: 5, accuracy: Low
        $x_5_4 = {8a 01 34 5c 88 45 fb 8b 55 fc 8a 45 fb 88 02 83 45 fc 01 73 05 e8 ?? ?? ?? ?? ff 45 f4 41 81 7d f4 ?? ?? 00 00 75 d9 81 c3 ?? ?? 00 00 73 05 e8 ?? ?? ?? ?? 89 5d f4 ff 75 f4 c3}  //weight: 5, accuracy: Low
        $x_5_5 = {32 c2 88 01 c3 [0-79] 8b ce b2 c0 8a 03 e8 ?? ?? ?? ?? 83 c6 01 73 05 e8 ?? ?? ?? ff ff 45 fc 43 81 7d fc ?? ?? 00 00 75 de 81 c7 ?? ?? 00 00 73 05 e8 ?? ?? ?? ff 89 7d fc ff 75 fc c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_JM_2147752435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.JM!MTB"
        threat_id = "2147752435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 12 80 f2 ?? 03 c3 73 ?? e8 ?? ?? ?? ff 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_JN_2147752436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.JN!MTB"
        threat_id = "2147752436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 88 45 ?? [0-16] 8b 45 ?? 89 45 ?? [0-16] 80 75 00 ?? [0-16] 8b 45 ?? 03 45 03 73 ?? e8 ?? ?? ?? ff 8a 55 00 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AN_2147753066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AN!MTB"
        threat_id = "2147753066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 f3 0f 6e c0 0f 6e 0b 0f ef c1 51 0f 7e c1 eb}  //weight: 1, accuracy: High
        $x_1_2 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 08 89 c8 eb}  //weight: 1, accuracy: High
        $x_1_3 = {66 31 0c 18 81 fb ?? ?? 00 00 7d 05 83 c3 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AN_2147753066_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AN!MTB"
        threat_id = "2147753066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 ?? 00 00 68 ?? ?? 00 00 6a 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 f8 33 c0 89 45 f4 ba ?? ?? ?? ?? 8a 02 88 45 ff b0 ?? 8a 5d ff 32 c3 8b 7d f8 03 7d f4 88 07 ff 45 f4 42 81 7d f4 ?? ?? 00 00 75 df ?? 00 00 00 00 [0-4] 00 00 03 ?? f8 ff ?? 8b e5 5d c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_H_2147753440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.H!MTB"
        threat_id = "2147753440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 [0-31] 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_5_2 = {8a 04 02 88 45 eb [0-159] 8a 55 eb 33 c2 [0-32] 8b 55 f0 88 02 [0-32] ff 45 f4 ff 4d e0 0f 85 ?? ?? ff ff}  //weight: 5, accuracy: Low
        $x_5_3 = {8a 04 02 88 45 f7 [0-159] 8a 55 f7 33 c2 [0-32] 8b 55 e4 88 02 [0-32] ff 45 f0 ff 4d e0 0f 85 ?? ?? ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_AU_2147753527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AU!MTB"
        threat_id = "2147753527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 5a 80 34 01 ?? 41 39 d1 75 f7 05 ?? ?? 00 00 ff e0 30 00 e8 ?? ff ff ff b8 ?? ?? ?? 00 31 c9 68 ?? ?? 00 00 5a}  //weight: 1, accuracy: Low
        $x_1_2 = {53 51 8b d8 54 6a 40 68 ?? ?? 00 00 53 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 5a 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AU_2147753527_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AU!MTB"
        threat_id = "2147753527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WScript.Sleep" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "schtasks /Run /TN" ascii //weight: 1
        $x_1_4 = "reg delete hkcu\\Environment /v windir /f && REM" ascii //weight: 1
        $x_1_5 = "reg add hkcu\\Environment /v windir /d \"cmd /c start" ascii //weight: 1
        $x_1_6 = "sc config WinDefend start= disabled" ascii //weight: 1
        $x_1_7 = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Sense\" /v \"Start\" /t \"REG_DWORD\" /d \"4\" /f" ascii //weight: 1
        $x_1_8 = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc\" /v \"Start\" /t \"REG_DWORD\" /d \"4\" /f" ascii //weight: 1
        $x_1_9 = "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiSpyware\" /t \"REG_DWORD\" /d \"1\" /f" ascii //weight: 1
        $x_1_10 = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\" /v \"Start\" /t \"REG_DWORD\" /d \"4\" /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_B_2147753528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.B!MTB!!Lokibot.A!MTB"
        threat_id = "2147753528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        info = "Lokibot: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WScript.Sleep" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "schtasks /Run /TN" ascii //weight: 1
        $x_1_4 = "reg delete hkcu\\Environment /v windir /f && REM" ascii //weight: 1
        $x_1_5 = "reg add hkcu\\Environment /v windir /d \"cmd /c start" ascii //weight: 1
        $x_1_6 = "sc config WinDefend start= disabled" ascii //weight: 1
        $x_1_7 = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Sense\" /v \"Start\" /t \"REG_DWORD\" /d \"4\" /f" ascii //weight: 1
        $x_1_8 = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc\" /v \"Start\" /t \"REG_DWORD\" /d \"4\" /f" ascii //weight: 1
        $x_1_9 = "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiSpyware\" /t \"REG_DWORD\" /d \"1\" /f" ascii //weight: 1
        $x_1_10 = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\" /v \"Start\" /t \"REG_DWORD\" /d \"4\" /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AT_2147753767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AT!MTB"
        threat_id = "2147753767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 1d c0 00 00 00 [0-16] 83 fb 00 74 ?? [0-16] eb}  //weight: 1, accuracy: Low
        $x_1_2 = {89 e0 83 c4 06 ff 28 e8 ?? ff ff ff c3}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 6e 0b 0f ef c1 51 [0-16] 0f 7e c1 88 c8 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AT_2147753767_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AT!MTB"
        threat_id = "2147753767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 0f b6 74 1d ff 8b c6 83 c0 df 83 e8 5e 73 1e 8b 04 24 e8 ?? ?? ?? ?? 8d 44 18 ff 50 8d 46 0e b9 5e 00 00 00 99 f7 f9 83 c2 21 58 88 10 43 4f 75 cf 5a 5d 5f 5e 5b c3}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 8b 44 24 1c 8b 40 24 e8 ?? ?? ?? ?? 50 8b 44 24 20 8b 40 08 50 8b 44 24 24 8b 40 0c 03 44 24 20 50 e8 ?? ?? ?? ?? 8b 44 24 18 83 c0 28 89 44 24 18 4b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_VD_2147754427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.VD!MTB"
        threat_id = "2147754427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc bf [0-64] 8a 01 34 ?? 8b d3 03 55 ?? 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_VD_2147754427_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.VD!MTB"
        threat_id = "2147754427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 02 88 45 [0-37] 8b 84 9d ?? ?? ?? ?? 03 84 bd [0-64] 8a 84 85 ?? ?? ?? ?? 32 45 ?? 8b 4d ?? 88 01 ff 45 ?? 42 ff 4d}  //weight: 2, accuracy: Low
        $x_1_2 = {8b ce c1 e1 ?? 8b fe c1 ef ?? 03 cf 0f be 3a 03 cf 33 f1 42 48 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_I_2147754504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.I!MTB"
        threat_id = "2147754504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_5_2 = {8b 45 f8 03 45 f0 89 45 ec [0-127] 25 ff 00 00 00 89 84 bd ?? ?? ff ff [0-47] 8a 02 88 45 e7 [0-79] 8a 84 85 ?? ?? ff ff 32 45 e7 8b 4d ec 88 01 [0-79] ff 45 f0 42 ff 4d e0 0f 85 ?? ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AO_2147754522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AO!MTB"
        threat_id = "2147754522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 89 8c 9d ?? ?? ff ff 25 ff 00 00 00 89 84 bd ?? ?? ff ff [0-16] 8a 02 88 45 ?? [0-16] 8b 84 9d ?? ?? ff ff 03 84 bd ?? ?? ff ff [0-16] 25 ff ?? ?? ?? 79 ?? 48 0d 00 ff ff ff 40 [0-16] 8a 84 85 ?? ?? ff ff 32 45 ?? 8b 4d ?? 88 01 [0-16] ff 45 ?? 42 ff 4d ?? 0f 85 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 55 68 ?? ?? ?? 00 64 ff 30 64 89 20 33 c0 a3 ?? ?? ?? 00 [0-16] 6a 00 58 f7 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AP_2147754588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AP!MTB"
        threat_id = "2147754588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 0a 01 f3 0f 6e c0 0f 6e 0b 0f ef c1 [0-16] 51 0f 7e c1 88 c8 59 [0-16] 29 f3 83 c3 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = {31 db 66 31 0c 18 81 fb ?? ?? 00 00 7d ?? 83 c3 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AQ_2147754724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AQ!MTB"
        threat_id = "2147754724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 38 4d 5a 00 00 66 39 01 0f 85 ?? 00 00 00 8b 41 ?? 03 c1 0f 84 ?? 00 00 00 81 38 50 45 00 00 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {36 38 5a ef 5f ed 57 89 46 ?? e8 ?? ?? 00 00 68 4d 12 1f 52 57 89 46 ?? e8 ?? ?? 00 00 68 1c d2 bc 89 57 89 46 ?? e8 ?? 00 00 68 7c 51 67 6a 57 89 46 ?? e8 ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {35 39 6a 6e 66 89 4d ?? 8b c8 66 89 4d ?? 59 6a 64 66 89 4d ?? 59 6a 62 66 89 4d ?? 59 6a 6f 66 89 4d ?? 59 6a 78 66 89 4d ?? 59 6a 6d 66 89 4d ?? 33 c9 66 89 4d ?? 59 6a 6c 66 89 4d ?? 8b c8 66 89 4d ?? 59 6a 77 66 89 4d ?? 59 6a 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AR_2147754730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AR!MTB"
        threat_id = "2147754730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 d2 03 11 bb ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 4a 39 1a eb}  //weight: 1, accuracy: Low
        $x_1_2 = {89 d3 8b 0f 31 f1 [0-5] 11 0c 18}  //weight: 1, accuracy: Low
        $x_1_3 = {46 ff 37 59 31 f1 39 c1 75}  //weight: 1, accuracy: High
        $x_1_4 = {01 c2 8b 1a ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AR_2147754730_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AR!MTB"
        threat_id = "2147754730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 30 64 89 20 33 c0 a3 ?? ?? ?? 00 [0-16] b8 00 00 00 00 f7 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 fc 5b 81 c3 ?? ?? 00 00 53 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 02 88 45 ?? [0-16] 8b 84 9d ?? ?? ff ff 03 84 bd ?? ?? ff ff [0-16] 25 ff 00 00 80 79 ?? 48 0d 00 ff ff ff 40 8a 84 85 ?? ?? ff ff 32 45 ?? 8b 4d ?? 88 01 [0-16] ff 45 ?? 42 ff 4d ?? 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AS_2147755279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AS!MTB"
        threat_id = "2147755279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 1d c0 00 00 00 83 fb 00 74 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {89 e0 83 c4 06 ff 28 e8 ?? ?? ff ff c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 04 0a 01 f3 0f 6e c0 0f 6e 0b 0f ef c1 51 e9 ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_J_2147755391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.J!MTB"
        threat_id = "2147755391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 39 d1 75 f7 1f 00 ba ?? ?? 00 00 31 c9 80 34 01 a3 41 39 d1 75 f7 05 ?? ?? 00 00 ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = {51 54 6a 40 68 ?? ?? 00 00 50 e8 ?? ?? ?? ff 5a c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_PC_2147755503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.PC!MTB"
        threat_id = "2147755503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5a 80 34 01 b2 41 39 d1 75 ?? 05 ?? ?? 00 00 ff e0 80 00 b8 ?? ?? ?? 00 50 e8 ?? ?? ?? ff b8 ?? ?? ?? 00 31 c9 68 ?? ?? 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = {53 51 8b d8 68 ?? ?? ?? 00 68 ?? ?? ?? 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 54 6a 40 68 ?? ?? 00 00 53 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AW_2147755554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AW!MTB"
        threat_id = "2147755554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f ef c1 51 0f 7e c1 88 c8 59 29 f3 83 c3 01 75 03 [0-5] 89 fb 89 04 0a 83 c1 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = {35 30 89 e0 83 c4 06 ff 28 e8 ?? ff ff ff c3}  //weight: 1, accuracy: Low
        $x_1_3 = {30 46 6e c0 0f 6e 0b eb}  //weight: 1, accuracy: High
        $x_1_4 = {64 8b 1d c0 00 00 00 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AV_2147755721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AV!MTB"
        threat_id = "2147755721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 8a 14 16 30 14 01 83 fe 14 75 04 33 f6 eb 01 46 30 1c 01 41 3b cf 72 e5}  //weight: 1, accuracy: High
        $x_1_2 = {8a 54 35 e4 30 14 08 83 fe 14 75 04 33 f6 eb 01 46 40 3b c7 72 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AV_2147755721_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AV!MTB"
        threat_id = "2147755721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 c1 0f 85 ?? ff ff ff 20 00 8b 0f [0-6] 31 f1 [0-8] 39 c1 0f 85 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c2 04 e9 ?? 00 00 00 40 00 8b 0f [0-16] 31 f1 [0-16] 11 0c 18 [0-16] 83 c2 04 e9 ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_BA_2147755801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.BA!MTB"
        threat_id = "2147755801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 1d c0 00 00 00 83 fb 00 74 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {50 89 e0 83 c4 06 ff 28 e8 ?? ?? ff ff c3}  //weight: 1, accuracy: Low
        $x_1_3 = {66 81 fb cd 03 0f 84 ?? 00 00 66 8b 18 66 81 fb 0f 0b 0f 84 ?? 00 00 ff d0 eb}  //weight: 1, accuracy: Low
        $x_1_4 = {80 fb cc 0f 84 ?? 00 00 66 8b 18 eb}  //weight: 1, accuracy: Low
        $x_1_5 = {81 ec 00 01 00 00 81 ed 00 01 00 00 61 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SS_2147758713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SS!MTB"
        threat_id = "2147758713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 c9 31 d2 6a 01 5e 81 c6 f7 72 00 00 87 d6 80 34 01 d6 41 89 d3 39 d9 75 f5}  //weight: 2, accuracy: High
        $x_1_2 = {80 34 01 d6 41 89 d3 39 d9 75 f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_AA_2147759133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AA!MTB"
        threat_id = "2147759133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 08 2d b1 30 14 67 05 b5 b9 c0 2b a6 82 79 16 b0 f7 85 e2 2c f9 82 fc 41 f9 3e 7d 6c 1b 3b 79 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_RI_2147762023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.RI!MTB"
        threat_id = "2147762023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 f7 f6 85 d2 75 [0-31] 8b c3 03 c1 [0-31] 80 30 9d [0-31] 41 81 f9 0f 08 01 00 75}  //weight: 10, accuracy: Low
        $x_10_2 = {33 d2 f7 f3 85 d2 75 [0-31] 8b c6 03 c1 [0-31] b2 [0-31] 30 10 [0-31] 41 81 f9 ?? ?? ?? ?? 75}  //weight: 10, accuracy: Low
        $x_10_3 = {33 d2 f7 f3 85 d2 75 [0-31] 8b ?? 03 d1 [0-31] b0 [0-31] 30 02 [0-31] 41 81 f9 0d 24 01 00 75}  //weight: 10, accuracy: Low
        $x_5_4 = {90 90 90 90 90 8a 84 85 e4 fb ff ff 32 45 eb 8b 55 ec 88 02 90 90 46 ff 4d e4 0f 85}  //weight: 5, accuracy: High
        $x_5_5 = {25 ff 00 00 00 89 84 bd ?? ?? ?? ?? 90 8b c6 3f 00 8b f8 90 [0-5] 8a 84 9d 00 [0-5] 8b 94 bd 00 89 94 9d 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_SV_2147766276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SV!MTB"
        threat_id = "2147766276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 f9 32 45 fb 88 01 83 e8 00 83 e8 00 83 e8 00 83 e8 00 8a 55 fa 8b c1 e8 ec fe ff ff eb 05 8a 45 f9 88 01 43 4e 75 95}  //weight: 1, accuracy: High
        $x_1_2 = {8b c8 83 e8 00 30 11 83 e8 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_VAL_2147772220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.VAL!MTB"
        threat_id = "2147772220"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "ToBase64String" ascii //weight: 1
        $x_1_3 = "GetResourceString" ascii //weight: 1
        $x_1_4 = "CompareString" ascii //weight: 1
        $x_1_5 = "StrReverse" ascii //weight: 1
        $x_1_6 = "$cb8b46e9-0b95-4885-91d4-33df6bd736c5" ascii //weight: 1
        $x_1_7 = "SimplePass.My.Resources" ascii //weight: 1
        $x_1_8 = "SimplePass.Form1.resources" ascii //weight: 1
        $x_1_9 = "SimplePass.Form2.resources" ascii //weight: 1
        $x_1_10 = "SimplePass.Quota.resources" ascii //weight: 1
        $x_1_11 = "SimplePass.Dashboard.resources" ascii //weight: 1
        $x_1_12 = "SimplePass.SearchPasswords.resources" ascii //weight: 1
        $x_1_13 = "SimplePass.Resources.resources" ascii //weight: 1
        $x_1_14 = "SimplePass.AboutSimplePass.resources" ascii //weight: 1
        $x_1_15 = "SimplePass.NewAccount.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_ALV_2147772221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.ALV!MTB"
        threat_id = "2147772221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vvOWkMj5G8URWQ2Hnhp" ascii //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "GetResourceString" ascii //weight: 1
        $x_1_4 = "HideModuleNameAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_6 = "RedCross.My.Resources" ascii //weight: 1
        $x_1_7 = "RedCross.login1.resources" ascii //weight: 1
        $x_1_8 = "RedCross.viewACT.resources" ascii //weight: 1
        $x_1_9 = "RedCross.mainfrm.resources" ascii //weight: 1
        $x_1_10 = "RedCross.viewstdinfo.resources" ascii //weight: 1
        $x_1_11 = "RedCross.IComperer.resources" ascii //weight: 1
        $x_1_12 = "RedCross.viewdnr.resources" ascii //weight: 1
        $x_1_13 = "RedCross.Resources.resources" ascii //weight: 1
        $x_1_14 = "RedCross.activities.resources" ascii //weight: 1
        $x_1_15 = "RedCross.viewMrks.resources" ascii //weight: 1
        $x_1_16 = "RedCross.marks.resources" ascii //weight: 1
        $x_1_17 = "RedCross.stdDetails.resources" ascii //weight: 1
        $x_1_18 = "RedCross.dnrdetails.resources" ascii //weight: 1
        $x_1_19 = "$B3E06F4D-8DA3-41BA-ACDF-6FA3408A1DF1" ascii //weight: 1
        $x_1_20 = "WILLSON & BROWN - WB Sp. z o.o. Sp. k." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_PD_2147773368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.PD!MTB"
        threat_id = "2147773368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 06 8d 04 80 8b 55 ?? 8b 54 ?? ?? 89 17 8b 55 ?? 8b 44 ?? ?? a3 ?? ?? ?? ?? 8b 07 3b 05 ?? ?? ?? ?? 73 16 a1 ?? ?? ?? ?? 31 07 8b 07 31 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 31 07}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_MFP_2147781041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.MFP!MTB"
        threat_id = "2147781041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {30 17 5e 1b 03 24 e2 67 dd 4d a2 67 30 41 0c fd b1 55 51 89 8d b1 0c 22 5c c2 df 2c ab 98 f4 ed ee 89 ef a7 29 b0 5b 3c 8b e9 a7 9e 19 cb a0 a6 ce 73 76 e6 55 d6 34 08 fe 34 19 52 75 13 fe d4 7c af ef 1d 3b 92 04 d3 1d f3 69 6e 21 64 6c 1c 59 76 9c 27 6d ad 5f 09 b6 0c 36 7f b0 10 d4 95 e8 a6 06 e4 90 c7 99 09 75 91 80 7a 41 d2 41 18}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_MFP_2147781041_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.MFP!MTB"
        threat_id = "2147781041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 75 08 ff 75 fc 58 59 90 01 c8 ff 30 90 90 59 90 91 34 c5 90 88 01 ff 45 fc 81 7d fc 78 5b 00 00 75}  //weight: 1, accuracy: High
        $x_1_2 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" ascii //weight: 1
        $x_1_3 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_4 = "MapVirtualKeyA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_MFP_2147781041_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.MFP!MTB"
        threat_id = "2147781041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\NCH Software\\ClassicFTP\\FTPAccounts" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\8pecxstudios\\Cyberfox86" ascii //weight: 1
        $x_1_3 = "DlRycq1tP2vSeaogj5bEUFzQiHT9dmKCn6uf7xsOY0hpwr43VINX8JGBAkLMZW" ascii //weight: 1
        $x_1_4 = "U2XpekVvtYq0fwsx7EDuZjrCo9GcF1B6Hl358mbznyLWdMANa4TSKJhIiOPgQR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_MFP_2147781041_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.MFP!MTB"
        threat_id = "2147781041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 95 c0 fd ff ff c7 85 ec fd ff ff ?? ?? ?? ?? eb 0f 8b 85 ec fd ff ff 83 c0 01 89 85 ec fd ff ff 8b 8d ec fd ff ff 3b 8d d8 fd ff ff 0f 83 37 01 00 00 8b 95 e4 fd ff ff 03 95 ec fd ff ff 8a 02 88 85 f3 fd ff ff 0f b6 8d f3 fd ff ff 83 e9 59 88 8d f3 fd ff ff 0f b6 95 f3 fd ff ff}  //weight: 10, accuracy: Low
        $x_10_2 = {ff 95 c0 fd ff ff c7 85 ec fd ff ff ?? ?? ?? ?? eb 0f 8b 85 ec fd ff ff 83 c0 01 89 85 ec fd ff ff 8b 8d ec fd ff ff 3b 8d d8 fd ff ff 0f 83 ee ?? ?? ?? 8b 95 e4 fd ff ff 03 95 ec fd ff ff 8a 02 88 85 f3 fd ff ff 0f b6 8d f3 fd ff ff 03 8d ec fd ff ff 88 8d f3 fd ff ff 0f b6 95 f3 fd ff ff}  //weight: 10, accuracy: Low
        $x_1_3 = "CloseClipboard" ascii //weight: 1
        $x_1_4 = "SetClipboardData" ascii //weight: 1
        $x_1_5 = "EmptyClipboard" ascii //weight: 1
        $x_1_6 = "OpenClipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_MFP_2147781041_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.MFP!MTB"
        threat_id = "2147781041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 8b 55 0c 83 c9 ff 56 8b 75 08 eb ?? 0f b6 06 4a 33 c8 46 6a 08 58 f6 c1 ?? 74 06 81 f1 54 ad 58 43 d1 e9 48 75 ?? 85 d2 75 ?? f7 d1 8b c1}  //weight: 10, accuracy: Low
        $x_1_2 = "Software\\NCH Software\\ClassicFTP\\FTPAccounts" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\8pecxstudios\\Cyberfox86" ascii //weight: 1
        $x_1_4 = "DlRycq1tP2vSeaogj5bEUFzQiHT9dmKCn6uf7xsOY0hpwr43VINX8JGBAkLMZW" ascii //weight: 1
        $x_1_5 = "U2XpekVvtYq0fwsx7EDuZjrCo9GcF1B6Hl358mbznyLWdMANa4TSKJhIiOPgQR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_RW_2147787196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.RW!MTB"
        threat_id = "2147787196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 03 00 00 00 f7 ?? 8b [0-5] 0f be 0c 10 8b [0-5] 0f [0-10] 33 c1 8b [0-5] 88 [0-10] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_GG_2147788248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.GG!MTB"
        threat_id = "2147788248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {90 90 8d 43 01 be 6e 00 00 00 33 d2 f7 f6 8b c1 03 c3 88 10 43 81 fb 58 39 70 1c}  //weight: 1, accuracy: High
        $x_1_2 = {a1 64 6e 48 00 03 c3 8a 00 90 34 9e 8b 15 64 6e 48 00 03 d3 88 02 90 90 43 81 fb bd 56 00 00 75 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_Inj_2147788934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.Inj!MTB"
        threat_id = "2147788934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e0 fd e6 e0 6c ee 43 fd e6 e0 fd 6c ee 47 e6 e0 fd e6 6c ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_Ink_2147789536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.Ink!MTB"
        threat_id = "2147789536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 95 dc fd ff ff 89 94 08 80 00 00 00 8b 86 bc 00 00 00 69 c0 84 00 00 00 03 86 c0 00 00 00 8d 8d f8 fd ff ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_DECC_2147793511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.DECC!MTB"
        threat_id = "2147793511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ca d1 e8 c1 e1 07 46 0b c8 03 cf 03 d1 0f be 3e 8b c2 85 ff 75 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_DECC_2147793511_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.DECC!MTB"
        threat_id = "2147793511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 71 b5 02 00 00 00 bc 29 40 00 cc 29 40 00 00 00 00 00 79 4f ad 33 99 66 cf 11 b7}  //weight: 1, accuracy: High
        $x_1_2 = "aaa_TouchMeNot_.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_MRVU_2147794309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.MRVU!MTB"
        threat_id = "2147794309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {23 38 3e 23 b2 30 99 38 3e 23 38 b2 30 a1 38 1c 16 07 b2 30 ad 1a 06 1a 13 b2 30 a9 01 55 3d 03 b2 30 b1 23 38 02 14 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_MV_2147794455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.MV!MTB"
        threat_id = "2147794455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xYohc4AEaYbNCS7ZeSVQKaFvSViWX" ascii //weight: 1
        $x_1_2 = "8b5clkVUSf2LeO9pE4VnofIuv" ascii //weight: 1
        $x_1_3 = {33 c0 8a c3 8a 98 48 30 46 00 33 c0 8a c3 8b d6}  //weight: 1, accuracy: High
        $x_1_4 = {6a 04 68 00 30 00 00 68 0b b6 3f 28 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_5 = {8a 00 88 45 ef 90 90 8a 45 ef 34 2d 8b 55 08 03 55 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_RMA_2147794744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.RMA!!Lokibot.gen!MTB"
        threat_id = "2147794744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "Lokibot: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "file:///" ascii //weight: 1
        $x_1_2 = "PK11SDR_Decrypt" ascii //weight: 1
        $x_1_3 = "HTTP Password" ascii //weight: 1
        $x_1_4 = "password_value" ascii //weight: 1
        $x_1_5 = "username_value" ascii //weight: 1
        $x_1_6 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins" ascii //weight: 1
        $x_1_7 = "Fuckav.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_HYJK_2147795086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.HYJK!MTB"
        threat_id = "2147795086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 00 32 00 74 00 57 00 50 00 6a 00 63 00 65 00 4b 00 39 00 72 00 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_KKLM_2147795088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.KKLM!MTB"
        threat_id = "2147795088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 50 a4 4c f8 fa bb 35 c3 7c ad 34 95 a5 2c e5 3d fe f2 04 0f 40 d1 62 b6 95 7e e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_UYTG_2147795090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.UYTG!MTB"
        threat_id = "2147795090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 00 00 00 b0 10 40 00 e0 33 40 00 b4 56 40 00 c0 56 40 00 f4 33 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SIS_2147795091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SIS!MTB"
        threat_id = "2147795091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8b 4d 08 0f b7 14 41 0f b6 8a ?? ?? ?? ?? c1 e1 04 8b 55 fc 8b 45 08 0f b7 54 50 02 0f b6 82 ?? ?? ?? ?? 0b c8 8b 45 fc 99 2b c2 d1 f8 88 4c 05 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {72 35 2c 36 36 36 51 36 fa 36 30 37 78 37 87 37 a6 37}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 45 ff 33 45 f8 88 45 ff 0f b6 45 ff 2d d8 00 00 00 88 45 ff}  //weight: 1, accuracy: High
        $x_1_4 = {0f b6 45 ff c1 f8 06 0f b6 4d ff c1 e1 02 0b c1 88 45 ff}  //weight: 1, accuracy: High
        $x_1_5 = {0f b6 7d db c1 e7 05 89 f1 09 f9 88 4d db 0f b6 75 db 89 f1 83 f1 36 88 4d db}  //weight: 1, accuracy: High
        $x_1_6 = {0f b6 4d db 83 c1 2b 88 4d db 8b 75 dc 0f b6 7d db 89 f9 31 f1 88 4d db 8b 75 dc}  //weight: 1, accuracy: High
        $x_1_7 = {0f b6 45 ff 33 45 f8 88 45 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 45 ff 83 e8 61}  //weight: 1, accuracy: High
        $x_1_8 = {83 7d 10 00 75 0c c7 45 fc 18 03 09 80 e9 7f 04 00 00 8b 4d 10 83 79 04 01 73 0c c7 45 fc 18 03}  //weight: 1, accuracy: High
        $x_1_9 = {89 45 e4 e8 f8 e5 ff ef 8b 4d f4 8d 15 08 c9 00 10 89 14 24 89 4c 24 04 89 44 24 08 8b 45 e4 89}  //weight: 1, accuracy: High
        $x_1_10 = {24 01 10 0f b6 3d f4 24 01 10 89 f9 29 f1 88 0d f4 24 01 10 8b 35 f0 24 01 10 0f b6 3d f4}  //weight: 1, accuracy: High
        $x_1_11 = {88 45 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 45 ff f7 d0 88 45 ff}  //weight: 1, accuracy: High
        $x_1_12 = {29 f1 88 4d df 0f b6 75 df 89 f1 83 f1 6f 88 4d df 0f b6 75 df 89 f1 81 e9 ab}  //weight: 1, accuracy: High
        $x_1_13 = {09 81 e9 49 54 53 46 0f 95 c3 0f b6 d3 83 fa 00}  //weight: 1, accuracy: High
        $x_1_14 = {83 c1 44 8b 55 0c 8b 75 08 89 34 24 89 54 24 04}  //weight: 1, accuracy: High
        $x_1_15 = {3e a6 c5 64 26 a8 df a2 4d 60 ca 24 db 29 da 9c a4 a5 e4 fc 55 eb a4 c0 7b 62 9c 5b 49 62 c2 d0}  //weight: 1, accuracy: High
        $x_1_16 = {e8 2b fb ff ff 83 c4 08 8b e5 5d c2 08 00 cc cc 55 8b ec 51 6a 20 e8 35 ea ff ff 83 c4 04 89 45}  //weight: 1, accuracy: High
        $x_1_17 = {89 45 fc 8b 4d 0c 51 8b 55 08 52 68 04 55 01 10 e8 8b ea ff ff 83 c4 0c 83 7d 0c 00 75 07 b8 03}  //weight: 1, accuracy: High
        $x_1_18 = {8b 40 1c 8b 4d ec 89 0c 24 8d 4d f0 89 4c 24 04 ff d0 83 ec 08 89 45 e4 8b 45 ec 8b 00 8b 40 08}  //weight: 1, accuracy: High
        $x_1_19 = {c4 04 89 45 fc 8b 4d 0c 51 8b 55 08 52 68 ec 55 01 10 e8 b9 e7 ff ff 83 c4 0c 83 7d 0c 00 75 07}  //weight: 1, accuracy: High
        $x_1_20 = {10 8d 43 04 6a 16 50 e8 91 f3 ff ff 83 c4 0c 85 c0 0f 85 9c 08 00 00 c6 43 03 06 33 c0 e9 47 08}  //weight: 1, accuracy: High
        $x_1_21 = {7c e2 ff ff 83 c4 08 50 68 c0 ba 02 10 e8 6e e2 ff ff 83 c4 08 8b 45 f8 83 c0 01 8b 4d 08 89 41}  //weight: 1, accuracy: High
        $x_1_22 = {8b 4d 0c 89 4d ec 8b 55 f8 3b 55 f0 73 19 8b 45 f8 8b 4d ec 0f b7 14 41 85 d2 74 0b 8b 45 f8 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Lokibot_DFGH_2147795826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.DFGH!MTB"
        threat_id = "2147795826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b1 d5 b7 29 ac e2 c6 29 bf b8 ce 25 d3 a6 dc 21 c5 9e d5 1e c7 ac e4 30 c5 a9 dd 25 d2 a9 e1 32 a6 bb c3 26 b1 bd}  //weight: 1, accuracy: High
        $x_1_2 = {e4 3f 46 00 cc 3f 46 00 b0 3f 46 00 a0 3f 46 00 84 3f 46 00 70 3f 46 00 54 3f 46 00 40 3f 46 00 2c 3f 46 00 18 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Lokibot_SISNE_2147797373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SISNE!MTB"
        threat_id = "2147797373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 55 14 52 8b 45 10 50 8b 4d 0c 51 8b 55 08 52}  //weight: 5, accuracy: High
        $x_5_2 = {35 8b 45 1c 99 2b c2 d1 f8 8b 55 18 0f b6 04 02}  //weight: 5, accuracy: High
        $x_10_3 = {5e e3 f5 06 81 62 35 2b 76 16 55 64 21 2b d1 68 86 c1 77 1b c9 8d 63 bb c3 d9 99 95 89 52 e4 69}  //weight: 10, accuracy: High
        $x_10_4 = {1b 9d cd bf 6d e1 23 ee 6b e0 3d a5 82 c1 7b df 01 3c 2d c4 2f 72 1e 88 f2 39 58 35 cb b6 c2 17}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_JHK_2147797374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.JHK!MTB"
        threat_id = "2147797374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 0c 00 66 8b 06 74 0e 66 3b 44 4d ?? 75 0e 66 8b ?? ?? ?? eb 13 66 3b ?? ?? ?? 74 07 41 3b cf 72 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_EM_2147797778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.EM!MTB"
        threat_id = "2147797778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 1e 90 8b 06 83 c0 01 73 05 e8 c2 a6 f8 ff 51 b9 38 00 00 00 33 d2 f7 f1 59 81 fa ff 00 00 00 76 05 e8 a2 a6 f8 ff 8b c1 03 06 73 05 e8 9f a6 f8 ff 88 10 90 43 81 fb 20 60 4e 1e 75 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_YTR_2147797883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.YTR!MTB"
        threat_id = "2147797883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 89 45 f8 ?? 8b 45 f8 05 ?? ?? ?? ?? 8a 00 34 27 8b d3 03 55 f8 88 02 ?? ?? ff 06 81 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_UIO_2147797884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.UIO!MTB"
        threat_id = "2147797884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 54 5a 73 42 69 32 63 68 64 00 00 52 4c 32 70 45 6b 6f 4b 54 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_DTY_2147797989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.DTY!MTB"
        threat_id = "2147797989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 65 4f 70 65 6e 00 f7 00 5f 5f 76 62 61 4e 65 77 32 00 a9 01 5f 61 64 6a 5f 66 64 69 76 5f 6d 33 32 69 00 00 ae 01 5f 61 64 6a 5f 66 64 69 76 72 5f 6d 33 32 69 00 ad 01 5f 61 64 6a 5f 66 64 69 76 72 5f 6d 33 32 00 00 ab 01 5f 61 64 6a 5f 66 64 69 76 5f 72 00 cf 00 5f 5f 76 62 61 49 34 56 61 72 00 00 62 01 5f 5f 76 62 61 56 61 72 44 75 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_UYT_2147797990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.UYT!MTB"
        threat_id = "2147797990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PPO324Em" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_POI_2147798658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.POI!MTB"
        threat_id = "2147798658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 0c 30 8a 09 90 80 f1 dc 8d 1c 30 88 0b 40 4a 75 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_INF_2147798661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.INF!MTB"
        threat_id = "2147798661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 34 18 8a 16 80 f2 8b 88 16 40 3d 72 57 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_INH_2147798662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.INH!MTB"
        threat_id = "2147798662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 f8 90 90 8b 55 f8 03 d3 8a 12 90 90 80 f2 20 8b 4d f8 03 cb 88 11 90 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_QWER_2147805594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.QWER!MTB"
        threat_id = "2147805594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BitConverter" ascii //weight: 1
        $x_1_2 = "System.IO.Compression" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "System.Net" ascii //weight: 1
        $x_1_6 = "DESCryptoServiceProvider" ascii //weight: 1
        $x_1_7 = "System.Threading" ascii //weight: 1
        $x_1_8 = "WriteLine" ascii //weight: 1
        $x_1_9 = "SuspendLayout" ascii //weight: 1
        $x_1_10 = "DownloadData" ascii //weight: 1
        $x_1_11 = "FromBase64String" ascii //weight: 1
        $x_1_12 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_13 = "StartsWith" ascii //weight: 1
        $x_1_14 = "Reverse" ascii //weight: 1
        $x_1_15 = "V2luZG93c0Zvcm1zQXBwMSQ=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_VALC_2147807575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.VALC!MTB"
        threat_id = "2147807575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 55 fc}  //weight: 1, accuracy: High
        $x_1_2 = "Windows Media Foundation\\ByteStreamHandlers" ascii //weight: 1
        $x_2_3 = {6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff}  //weight: 2, accuracy: High
        $x_2_4 = {89 45 dc c7 04 24 00 00 00 00 c7 44 24 04 00 a3 e1 11 c7 44 24 08 00 30 00 00 c7 44 24 0c 04 00 00 00 89 4d d8 ff 55}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_RT_2147808756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.RT!MTB"
        threat_id = "2147808756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ahaty" ascii //weight: 1
        $x_1_2 = "bpuzplozj" ascii //weight: 1
        $x_1_3 = "ccri" ascii //weight: 1
        $x_1_4 = "hwhoyd" ascii //weight: 1
        $x_1_5 = "pthfhtcqh" ascii //weight: 1
        $x_1_6 = "swohdluyyih" ascii //weight: 1
        $x_1_7 = "vrpvwvdy" ascii //weight: 1
        $x_1_8 = "wudmv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SIB_2147813234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SIB!MTB"
        threat_id = "2147813234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Avotax Builder" wide //weight: 1
        $x_1_2 = {5f 66 0f 66 c9 [0-128] b8 ?? ?? ?? ?? [0-181] 35 ?? ?? ?? ?? a0 02 05 ?? ?? ?? ?? aa 01 81 34 07 ?? ?? ?? ?? [0-165] 83 c0 04 [0-165] 3d ?? ?? ?? ?? [0-10] 0f 85 ?? ?? ?? ?? [0-5] 83 f0 00 [0-90] ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SIBA_2147813235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SIBA!MTB"
        threat_id = "2147813235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Murex" wide //weight: 1
        $x_1_2 = {66 0f ec e5 0f [0-90] 81 34 1a ?? ?? ?? ?? [0-48] 43 [0-53] 43 [0-42] 43 [0-64] 43 [0-58] 81 fb 8c 0d 01 00 [0-5] 0f 85 ?? ?? ?? ?? bd 01 ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_SIBA_2147813235_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.SIBA!MTB"
        threat_id = "2147813235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "curogayeneso-kuconunegonu\\yacibav-betecibutemek\\gidiji.pdb" ascii //weight: 1
        $x_1_2 = {8b c7 c1 e0 04 89 45 ?? [0-64] 8b 45 ?? 8d 0c 38 8b 45 ?? c1 e8 ?? 89 45 ?? 31 4d 00 8b 45 05 8b 4d ?? 03 c1 33 45 00 [0-32] 89 45 05 75 ?? [0-16] 8b 45 05 29 45 ?? [0-32] 8b 75 0f [0-10] 8b c6 d3 e0 8b 4d 02 8b d6 c1 ea ?? 03 45 ?? 03 55 ?? 03 ce 33 c1 33 c2 2b f8 89 55 05 [0-10] 89 7d 03 8b 45 ?? 29 45 02 ff 4d ?? 0f 85 ?? ?? ?? ?? 8b 45 08 8b 4d 0f 89 38 [0-10] 89 48 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_RPV_2147833368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.RPV!MTB"
        threat_id = "2147833368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 da 88 55 ff 0f b6 45 ff 03 45 f8 88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 8b 55 f4 03 55 f8 8a 45 ff 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_CRUM_2147848275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.CRUM!MTB"
        threat_id = "2147848275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 2c 24 04 01 04 24 8b 04 24 31 01}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 14 8b 44 24 10 33 d7 33 c2 2b d8 81 3d [0-9] 89 44 24 10 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lokibot_AEMA_2147934364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.AEMA!MTB"
        threat_id = "2147934364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EXECUTE ( \"D\" & \"ll\" & \"Ca\" & \"ll\" )" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"B\" & \"ina\" & \"ryLen\" )" ascii //weight: 1
        $x_1_3 = "EXECUTE ( \"File\" & \"Open\" )" ascii //weight: 1
        $x_1_4 = "EXECUTE ( \"File\" & \"Read\" )" ascii //weight: 1
        $x_2_5 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_6 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-20] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_3_7 = {28 00 20 00 22 00 65 00 6b 00 6e 00 22 00 20 00 26 00 20 00 22 00 72 00 6c 00 65 00 32 00 33 00 64 00 2e 00 6c 00 6c 00 22 00 20 00 29 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 6f 00 62 00 22 00 20 00 26 00 20 00 22 00 6c 00 6f 00 22 00 20 00 29 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 69 00 56 00 74 00 72 00 61 00 22 00 20 00 26 00 20 00 22 00 75 00 50 00 6c 00 6f 00 72 00 65 00 74 00 74 00 63 00 22 00 20 00 29 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 74 00 70 00 22 00 20 00 26 00 20 00 22 00 72 00 22 00 20 00 29 00 20 00 2c 00}  //weight: 3, accuracy: Low
        $x_3_8 = {28 20 22 65 6b 6e 22 20 26 20 22 72 6c 65 32 33 64 2e 6c 6c 22 20 29 20 2c 20 [0-20] 20 28 20 22 6f 62 22 20 26 20 22 6c 6f 22 20 29 20 2c 20 [0-20] 20 28 20 22 69 56 74 72 61 22 20 26 20 22 75 50 6c 6f 72 65 74 74 63 22 20 29 20 2c 20 [0-20] 20 28 20 22 74 70 22 20 26 20 22 72 22 20 29 20 2c}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lokibot_LIT_2147937990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokibot.LIT!MTB"
        threat_id = "2147937990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 44 16 01 88 85 00 fd ff ff 83 f0 cc 88 44 13 01 8d 42 02 39 f8 73 0c 0f b6 44 16 ?? 83 f0 cc 88 44 13 02 83 bd 04 fd ff ff 0e 0f 86}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

