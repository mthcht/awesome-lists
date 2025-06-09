rule Trojan_Win64_DonutLoader_TL_2147940639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DonutLoader.TL!MTB"
        threat_id = "2147940639"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b9 04 00 00 00 41 b8 00 30 00 00 31 c9 ba 00 00 50 00 ff d0 49 89 c5 48 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DonutLoader_TL_2147940639_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DonutLoader.TL!MTB"
        threat_id = "2147940639"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 98 0f b6 4c 05 80 8b 85 84 00 00 00 48 63 d0 48 8b 85 a0 00 00 00 48 01 d0 44 89 c2 31 ca 88 10 83 85 84 00 00 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DonutLoader_BG_2147943164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DonutLoader.BG!MTB"
        threat_id = "2147943164"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {46 0f b6 0c 0a 45 89 c2 41 83 f2 ff 44 89 ca 44 21 d2 41 83 f1 ff 45 21 c8 44 09 c2 48 8b 00 48 8b 09 88 14 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

