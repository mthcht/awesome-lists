rule Trojan_Win32_MysticStealer_AMS_2147891518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MysticStealer.AMS!MTB"
        threat_id = "2147891518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 0c 97 95 e9 d1 5b 42 69 f6 95 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 95 e9 d1 5b 33 f1 3b d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MysticStealer_AMC_2147891522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MysticStealer.AMC!MTB"
        threat_id = "2147891522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 0c 38 34 f3 0f b6 c0 66 89 84 4c ?? ?? ?? ?? 41 83 f9 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MysticStealer_RPZ_2147892555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MysticStealer.RPZ!MTB"
        threat_id = "2147892555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d3 80 2c 3e 70 ff d3 80 04 3e d6 ff d3 80 34 3e a3 ff d3 80 04 3e 77 ff d3 80 04 3e 5b ff d3 80 04 3e 60 ff d3 80 04 3e f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MysticStealer_RPX_2147892672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MysticStealer.RPX!MTB"
        threat_id = "2147892672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d3 80 04 3e 1c ff d3 80 04 3e fa ff d3 80 34 3e 4b ff d3 80 04 3e 7a ff d3 80 04 3e c0 ff d3 80 04 3e 6e ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MysticStealer_ASAX_2147892679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MysticStealer.ASAX!MTB"
        threat_id = "2147892679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff d6 80 34 2f ?? ff d6 80 04 2f ?? ff d6 80 04 2f ?? ff d6 80 04 2f ?? 47 3b fb 0f 82}  //weight: 5, accuracy: Low
        $x_5_2 = {ff d6 80 34 ?? fc ff d6 fe 04 2f ff d6 80 04 2f ?? ff d6 80 04 2f ?? 47 3b fb 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_MysticStealer_ASAY_2147892711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MysticStealer.ASAY!MTB"
        threat_id = "2147892711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff d6 80 34 2f ?? ff d6 80 04 2f ?? ff d6 ff d6 80 04 2f ?? ff d6 80 04 2f ?? ff d6 80 04 2f}  //weight: 5, accuracy: Low
        $x_5_2 = {ff d6 80 34 2f ?? ff d6 80 04 2f ?? ff d6 80 04 2f ?? ff d6 47 3b fb 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_MysticStealer_MBJH_2147892725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MysticStealer.MBJH!MTB"
        threat_id = "2147892725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 80 04 2f ?? ff d6 80 34 2f ?? ff d6 ff d6 80 04 2f ?? ff d6 80 04 2f ?? 47 3b fb 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MysticStealer_ASAZ_2147892730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MysticStealer.ASAZ!MTB"
        threat_id = "2147892730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 80 04 2f ?? ff d6 80 34 2f ?? ff d6 fe 04 2f ff d6 80 04 2f ?? ff d6 80 04 2f ?? 47 3b fb 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MysticStealer_CCEA_2147896565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MysticStealer.CCEA!MTB"
        threat_id = "2147896565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 38 ?? 0f b6 87 ?? ?? ?? ?? 0f b6 44 38 ?? 03 c8 0f b6 c1 8d 4f ?? 8a 04 08 30 04 13 43 3b 5d ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MysticStealer_ASES_2147900221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MysticStealer.ASES!MTB"
        threat_id = "2147900221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "foitgsdmyifkmmfbcyyqmchjvxsrjzjikbpjvejpnbizogohwmsbllmmfpdhacryhcsxiza" ascii //weight: 1
        $x_1_2 = "uejxrgtujpheolxnkypdauzdofofhdxrbsmzc" ascii //weight: 1
        $x_1_3 = "kqamneztzfzntwlxqlyfzbfhw" ascii //weight: 1
        $x_1_4 = "qcnhgqusfxdeqbymhfuebovykycrycnrqjiukwfwxhupeyobunrdfbeprdwhk" ascii //weight: 1
        $x_1_5 = "ombmfjhimarvcpjmvnzqlgvrqhpcfnqbmullxykbnfqxyavoi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MysticStealer_CCHC_2147901318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MysticStealer.CCHC!MTB"
        threat_id = "2147901318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MysticStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fd ff ff 0f b6 85 ?? fd ff ff 8b 4d 08 03 8d ?? fd ff ff 0f b6 11 33 d0 8b 45 08 03 85 ?? fd ff ff 88 10 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

