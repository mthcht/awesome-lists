rule Trojan_Win64_Zbot_BL_2147824734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zbot.BL!MTB"
        threat_id = "2147824734"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 f1 8b c2 8b c0 48 8b 4c 24 ?? 0f be 04 01 48 8b 4c 24 ?? 48 8b 54 24 ?? 0f b6 0c 11 33 c8 8b c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zbot_CCIH_2147911577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zbot.CCIH!MTB"
        threat_id = "2147911577"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c1 89 44 24 ?? 35 ?? ?? ?? ?? 89 44 24 ?? 89 c8 35 ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 3b 44 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zbot_GVA_2147937569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zbot.GVA!MTB"
        threat_id = "2147937569"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 83 e2 01 83 fa 01 19 d2 83 e2 3e 83 ea 7b 30 14 07 48 ff c0 39 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

