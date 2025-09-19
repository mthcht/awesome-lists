rule Trojan_Win64_AgentTesla_GVI_2147951451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentTesla.GVI!MTB"
        threat_id = "2147951451"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 54 16 10 41 03 d1 44 0f b6 e2 43 8d 14 a4 ff c2 44 0f b6 e2 8b d1 0f b6 44 13 10 44 8b c8 41 d1 f9 c1 e0 07 41 0b c1 0f b6 c0 41 33 c4 41 88 44 16 10 ff c1 3b e9 7f 9d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AgentTesla_GVJ_2147952579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentTesla.GVJ!MTB"
        threat_id = "2147952579"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 8b d8 44 33 5c 24 40 41 8b cb 8b 44 24 38 89 44 24 40 44 8b 54 24 3c 41 ff ca 89 4c 24 44 79 bb}  //weight: 2, accuracy: High
        $x_1_2 = {45 0f b6 5c 10 10 44 03 d8 41 8b c3 41 33 c1 ff c2 44 3b d2 7f ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AgentTesla_GVK_2147952580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentTesla.GVK!MTB"
        threat_id = "2147952580"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 8b c0 99 f7 ff 3b d7 73 ?? 44 8b d2 46 0f b6 54 16 10 44 3b 41 08 73 ?? 41 8b c0 44 88 54 01 10 41 ff c0 44 3b c3 7c d7}  //weight: 2, accuracy: Low
        $x_2_2 = {4c 8b 09 49 c1 c1 38 4c 03 0a 44 8b d8 4f 33 4c d8 10 4c 89 09 4c 8b 0a 49 c1 c1 03 4c 33 09 4c 89 0a ff c0 44 3b d0 7f d7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_AgentTesla_GVL_2147952581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentTesla.GVL!MTB"
        threat_id = "2147952581"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8d 04 17 44 3b c5 0f 83 88 00 00 00 45 8b d0 46 0f b6 4c 13 10 44 8b da 48 8b 4c 24 20 46 0f b6 5c 19 10 45 33 cb 45 3b 47 08 73 68 47 88 4c 17 10 ff c2 3b d0 7c c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

