rule Trojan_Win64_Gobin_GVA_2147971867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gobin.GVA!MTB"
        threat_id = "2147971867"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 0f 1f 84 00 00 00 00 00 85 c0 0f 84 15 04 00 00 69 d0 62 6c 00 00 c1 e8 10 31 d0 a9 0f 00 00 00 74 dc 89 c2 c1 e8 12 90 83 f8 20 77 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Gobin_GVB_2147972455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gobin.GVB!MTB"
        threat_id = "2147972455"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8d a4 24 88 f2 ff ff 4d 3b 66 10 0f 86 64 12 00 00 55 48 89 e5 48 81 ec f0 0d 00 00 48 89 84 24 00 0e 00 00 b9 af 57 00 00 eb 02 31 c9 85 c9 0f 84 61 03 00 00 81 f1 17 0a 00 00 83 e1 0f 90 48 83 f9 0a 77 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

