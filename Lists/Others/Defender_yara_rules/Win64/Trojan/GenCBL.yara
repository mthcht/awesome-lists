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

rule Trojan_Win64_GenCBL_GMF_2147973027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GenCBL.GMF!MTB"
        threat_id = "2147973027"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GenCBL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 89 e1 32 0c 07 88 4d db 44 0f b6 4d db 44 0f b6 55 db 45 0f b6 d2 41 c1 fa 04 41 c1 e1 04 45 09 d1 44 88 4d db 0f b6 55 db f7 d2 88 55 db 88 0c 06 48 83 c0 01 39 c3 7f c6}  //weight: 10, accuracy: High
        $x_1_2 = "sub_nybo_7" ascii //weight: 1
        $x_1_3 = "sub_nu95_0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

