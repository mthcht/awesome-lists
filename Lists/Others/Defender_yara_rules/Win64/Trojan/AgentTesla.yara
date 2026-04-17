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

rule Trojan_Win64_AgentTesla_DI_2147957582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentTesla.DI!MTB"
        threat_id = "2147957582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "8197543738:AAGRcN3RWZO_nMCKUJ37nPJD7CxbQrz7GMo" ascii //weight: 4
        $x_4_2 = "stealer-main\\stealer-main\\build\\output\\build.pdb" ascii //weight: 4
        $x_3_3 = "7884746925" ascii //weight: 3
        $x_2_4 = "<b>NEW VICTIM CONNECTED</b>" ascii //weight: 2
        $x_1_5 = "<b>USER INFO</b>" ascii //weight: 1
        $x_1_6 = "Computer: <code>" ascii //weight: 1
        $x_1_7 = "Public IP: <code>" ascii //weight: 1
        $x_1_8 = "<b>NETWORK INFO</b>" ascii //weight: 1
        $x_1_9 = "chat_id=" ascii //weight: 1
        $x_1_10 = "screenshot.png" ascii //weight: 1
        $x_1_11 = "api.telegram.org" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AgentTesla_ABRS_2147967052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentTesla.ABRS!MTB"
        threat_id = "2147967052"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 d1 42 32 0c 2b 42 88 0c 2f 49 ff c5 4d 39 ee ?? ?? ?? ?? ?? ?? 44 89 ea c1 ea ?? 44 89 e9 c1 e9 ?? 45 89 e8 41 83 e0 ?? 4e 63 04 80 49 01 c0 41 ff e0 89 d1 eb cb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AgentTesla_AZPZ_2147967242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentTesla.AZPZ!MTB"
        threat_id = "2147967242"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 44 24 20 8b 44 24 20 c1 e8 10 88 44 24 27 48 89 f9 48 83 c1 04 48 8b 54 24 28 e8 ?? ?? ?? ?? 0f b6 18 0f b6 44 24 27 31 c3 48 8b 54 24 28 48 89 f1 e8 ?? ?? ?? ?? 88 18 48 8b 44 24 28 48 83 c0 01 48 89 44 24}  //weight: 5, accuracy: Low
        $x_5_2 = {31 c8 88 44 24 ?? 48 8b 44 24 ?? 48 8b 4c 24 ?? 0f b6 04 08 0f b6 4c 24 ?? 31 c8 88 c2 48 8b 44 24 ?? 48 8b 4c 24 ?? 88 14 08 48 8b 44 24 08 48 83 c0 ?? 48 89 44 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

