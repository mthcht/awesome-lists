rule Trojan_Win64_Asyncrat_LM_2147948582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Asyncrat.LM!MTB"
        threat_id = "2147948582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Asyncrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 83 ec 28 48 85 d2 74 2d 83 7a 08 06 75 ?? 48 b8 46 00 6f 00 72 00 6d 00 48 33 42 0c 44 8b 42 14 41 81 f0 61 00 74 00 49 0b c0 75 ?? 48 8b 81 88 00 00 00 eb}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Asyncrat_PGAS_2147958623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Asyncrat.PGAS!MTB"
        threat_id = "2147958623"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Asyncrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 03 c8 0f b6 c1 0f b6 4c 05 10 30 0c 1f 48 8d 4d 10 41 0f b6 c2 4c 03 c0 41 0f b6 10 45 8d 1c 11 41 0f b6 c3 48 03 c8 0f b6 01 41 88 00 88 11 41 0f b6 08 48 03 ca 0f b6 c1 0f b6 4c 05 10 30 4c 1f 01 48 83 c3 02 48 81 fb ?? ?? ?? ?? 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Asyncrat_KK_2147959013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Asyncrat.KK!MTB"
        threat_id = "2147959013"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Asyncrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 03 ca 0f b6 c1 0f b6 4c 05 10 42 30 4c 1b 04 41 fe c1 4c 8d 45 10 41 0f b6 c1 48 8d 4d 10 4c 03 c0 41 0f b6 10 44 02 d2 41 0f b6 c2 48 03 c8 0f b6 01 41 88 00 88 11 41 0f b6 08 48 03 ca 0f b6 c1 0f b6 4c 05 10 42 30 4c 1b 05 49 83 c3 06 49 81 fb}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

