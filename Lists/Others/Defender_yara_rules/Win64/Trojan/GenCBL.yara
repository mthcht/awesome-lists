rule Trojan_Win64_GenCBL_ARA_2147897645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GenCBL.ARA!MTB"
        threat_id = "2147897645"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GenCBL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 41 f6 30 44 0c 20 48 ff c1 48 83 f9 08 72 f0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GenCBL_ARA_2147897645_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GenCBL.ARA!MTB"
        threat_id = "2147897645"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GenCBL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 42 04 30 44 15 e0 48 ff ?? 48 83 fa ?? 72 f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

