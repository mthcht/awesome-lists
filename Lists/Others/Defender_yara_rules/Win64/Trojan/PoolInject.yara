rule Trojan_Win64_PoolInject_GA_2147933552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.GA!MTB"
        threat_id = "2147933552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 4c 24 28 33 c8 8b c1 89 44 24 24 8b 44 24 2c 89 44 24 28 eb b9}  //weight: 3, accuracy: High
        $x_3_2 = {0f b6 c8 48 8b 44 24 38 48 d3 e8 48 25 ff 00 00 00 48 63 4c 24 24 48 8b 54 24 28 48 03 d1 48 8b ca 48 8b 54 24 30 88 04 0a}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_PoolInject_BR_2147935039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.BR!MTB"
        threat_id = "2147935039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {45 33 ca 49 c1 e1 20 4c 0b c9 49 8b c9 45 88 0c 03 48 c1 e9 08 41 88 4c 03 01}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 0c 2f 4c 8d 1c 2f 45 0f b6 4b 01 49 c1 e1 08 4c 0b c9}  //weight: 2, accuracy: High
        $x_1_3 = {45 88 4c 03 ?? 41 88 4c 03 ?? 48 83 c7 08 48 81 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_GVA_2147941529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.GVA!MTB"
        threat_id = "2147941529"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 00 41 0f b6 81 ?? ?? ?? ?? 42 0f b6 14 0a 42 32 14 08 43 30 14 10 49 ff c2 48 8b 41 08 4c 3b 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

