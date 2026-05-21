rule Trojan_Win64_DragonWhistle_PAHJ_2147969884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DragonWhistle.PAHJ!MTB"
        threat_id = "2147969884"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DragonWhistle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 04 24 ff c0 89 04 24 8b 44 24 ?? 39 04 24 7d ?? 48 63 04 24 48 8b 4c 24 ?? 0f b6 04 01 83 f0 42 48 63 0c 24 48 8b 54 24 ?? 66 89 04 4a eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

