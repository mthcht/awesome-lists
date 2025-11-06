rule Trojan_Win64_Blackshrantac_Z_2147954864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blackshrantac.Z!MTB"
        threat_id = "2147954864"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blackshrantac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c8 80 e1 07 c0 e1 03 49 8b d0 48 d3 ea 66 41 23 d1 66 31 14 43 48 ff c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Blackshrantac_SB_2147955195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blackshrantac.SB!MTB"
        threat_id = "2147955195"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blackshrantac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BLACK-SHRANTAC" wide //weight: 1
        $x_1_2 = "Your files have been extracted from your network and encrypted" wide //weight: 1
        $x_1_3 = "we are solely motivated by financial compensation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Blackshrantac_SA_2147956958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blackshrantac.SA!MTB"
        threat_id = "2147956958"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blackshrantac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c8 80 e1 ?? c0 e1 ?? 49 8b d0 48 d3 ea 66 41 23 d1 66 31 14 43 48 ff c0 48 83 f8 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

