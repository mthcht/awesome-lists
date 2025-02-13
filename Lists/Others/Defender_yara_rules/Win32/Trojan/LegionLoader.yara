rule Trojan_Win32_LegionLoader_ALE_2147835167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LegionLoader.ALE!MTB"
        threat_id = "2147835167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LegionLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AOIANmvigsjg34sioh" ascii //weight: 1
        $x_1_2 = "LapqpdogTicvbsoh" ascii //weight: 1
        $x_1_3 = "asopef3jghiosrjh49heo" ascii //weight: 1
        $x_1_4 = "iodrgoigjw4jhi4" ascii //weight: 1
        $x_1_5 = "iosgoijs4jjgsriohj" ascii //weight: 1
        $x_1_6 = "ocvoiboigj34980gserjioh" ascii //weight: 1
        $x_1_7 = "xciovbisfghjwghw" ascii //weight: 1
        $x_1_8 = "xiocviobsjgw34gjih" ascii //weight: 1
        $x_1_9 = "zovieoigfw3j98rjh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LegionLoader_RPQ_2147835587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LegionLoader.RPQ!MTB"
        threat_id = "2147835587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LegionLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 83 c9 fc 41 85 c9 74 12 83 7d d8 00 7e 0c 8b 55 d8 81 c2 ?? ?? ?? ?? 89 55 d8 8b 45 90 8b 4d bc 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LegionLoader_RPR_2147835701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LegionLoader.RPR!MTB"
        threat_id = "2147835701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LegionLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4d fc 8b 55 fc 03 55 b0 89 55 fc 8b 45 f4 03 45 f8 89 45 f4 8b 4d fc 2b 4d b0 89 4d fc 8b 55 f8 2b 55 f4 89 55 f8 8b 45 f4 03 45 f8 89 45 f4 8b 8d 58 ff ff ff 8b 55 98 89 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LegionLoader_RPS_2147835702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LegionLoader.RPS!MTB"
        threat_id = "2147835702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LegionLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 55 b8 8b 45 b0 2d ?? ?? ?? ?? 89 45 b0 8b 4d c4 81 e9 ?? ?? ?? ?? 89 4d c4 8b 55 cc 03 55 c0 89 55 cc 8b 45 c4 2b 45 ac 89 45 c4 8b 4d c0 81 c1 ?? ?? ?? ?? 89 4d c0 8b 95 ?? ?? ?? ?? 8b 45 94 89 02}  //weight: 1, accuracy: Low
        $x_1_2 = {74 0b 8b 55 d8 83 c2 01 89 55 d8 eb e6 8b 45 a8 2b 45 d8 89 45 a8 8b 4d b8 81 e9 f3 1c 00 00 89 4d b8 8b 95 2c ff ff ff 8b 85 74 ff ff ff 89 02 90 90 90 90 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LegionLoader_A_2147837870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LegionLoader.A!MTB"
        threat_id = "2147837870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LegionLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 08 00 00 00 6b c8 00 ba 78 65 63 2e c7 44 0d e8 6d 73 69 65 89 54 0d ec c7 45 e4 eb 16 a3 12 b8 08 00 00 00 c1 e0 00 33 c9 c7 44 05 e8 65 78 65 00 89 4c 05 ec 8d 55 e8 52 8b 45 f8 50 ff 15 30 ?? 04 10 85 c0 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LegionLoader_BL_2147838837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LegionLoader.BL!MTB"
        threat_id = "2147838837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LegionLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "IoaspgsogBskbovejgwe" ascii //weight: 2
        $x_2_2 = "dfiosogos4j9gj9h" ascii //weight: 2
        $x_2_3 = "iosoigs498gjs4ehj" ascii //weight: 2
        $x_2_4 = "sdiogoisgj40gsrjh4" ascii //weight: 2
        $x_2_5 = "soigfsoieg4jsrhdh" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LegionLoader_RF_2147840393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LegionLoader.RF!MTB"
        threat_id = "2147840393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LegionLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 8b 08 c1 e1 06 8b 55 f4 8b 02 c1 e8 08 33 c8 8b 55 f4 8b 32 03 f1 8b 45 fc 33 d2 f7 75 ec 8b 45 08 03 34 90 03 75 fc 8b 4d f0 8b 11 2b d6 8b 45 f0 89 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LegionLoader_CPP_2147841034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LegionLoader.CPP!MTB"
        threat_id = "2147841034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LegionLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "iovgseiogje894gseijhsre" ascii //weight: 5
        $x_5_2 = "oqwopeiogjseagoseihj" ascii //weight: 5
        $x_5_3 = "shioswejg38w9goseijseh" ascii //weight: 5
        $x_5_4 = "siosejgf3w8geiojseh" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LegionLoader_AABX_2147849186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LegionLoader.AABX!MTB"
        threat_id = "2147849186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LegionLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Jioafuaiofaofs" ascii //weight: 1
        $x_1_2 = "Npoadpofajiofgad" ascii //weight: 1
        $x_1_3 = "Poafoadjfiadj" ascii //weight: 1
        $x_1_4 = "QRcode_encodeString" ascii //weight: 1
        $x_1_5 = "UIaiaogfiasdjgasdgj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LegionLoader_AAGB_2147851079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LegionLoader.AAGB!MTB"
        threat_id = "2147851079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LegionLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Epapoaeofafgajdi" ascii //weight: 2
        $x_2_2 = "Faiofoiafaioejghae" ascii //weight: 2
        $x_2_3 = "Iiadifoaiodfjgaeihg" ascii //weight: 2
        $x_2_4 = "Oaeopifgaeopgja" ascii //weight: 2
        $x_2_5 = "Oaofgaeiogjadsigh" ascii //weight: 2
        $x_2_6 = "Oosagisjgsiegsuh" ascii //weight: 2
        $x_2_7 = "Upsrgiwosergjwigjadsf" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

