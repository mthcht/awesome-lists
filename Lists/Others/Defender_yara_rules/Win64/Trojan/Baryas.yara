rule Trojan_Win64_Baryas_MBXS_2147919872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Baryas.MBXS!MTB"
        threat_id = "2147919872"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Baryas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 6c 6c 2e 64 6c 6c 00 44 6c 6c 4c 6f 61 64 00 44 6c 6c 4c 6f 61 64 58 00 50 32 50 4d 61 69 6e 53 74 61 72 74 00 50 32 50 4e 65}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Baryas_MBXY_2147923991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Baryas.MBXY!MTB"
        threat_id = "2147923991"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Baryas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 6c 6c 4c 6f 61 64 00 44 6c 6c 4c 6f 61 64 58 00 50 32 50 4d 61 69 6e 53 74 61 72 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

