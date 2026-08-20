rule Trojan_Win64_GCleaner_LVK_2147969877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GCleaner.LVK!MTB"
        threat_id = "2147969877"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d c8 03 fa 03 fb 03 f8 6a 00 ?? ?? ?? ?? ?? 31 3e 83 c3 04 83 c6 04 3b 5d cc 72 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GCleaner_SA_2147976564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GCleaner.SA!MTB"
        threat_id = "2147976564"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GCleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "XpSimulateParanoid" ascii //weight: 3
        $x_3_2 = "Average ymcjteezpitktwqnwtxv Record coquwmiwfyfauikjeczmv Record artfsohjmxqyehsciqoqu Average xtrzpaikurvocdgvbxia" ascii //weight: 3
        $x_3_3 = "LlLtLuMnosmidnil125625NaN m=finptrobj()" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

