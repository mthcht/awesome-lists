rule Trojan_MSIL_Purelog_MX_2147963811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelog.MX!MTB"
        threat_id = "2147963811"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 01 11 05 16 11 06 6f 0d 00 00 0a 38 00 00 00 00 11 04 11 05}  //weight: 1, accuracy: High
        $x_1_2 = {11 04 11 05 16 11 05 8e 69 6f 0b 00 00 0a 25 13 06 16 3d 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Purelog_MX_2147963811_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelog.MX!MTB"
        threat_id = "2147963811"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Qibanonana.pdb" ascii //weight: 1
        $x_1_2 = "S2um4DXYAxufWRrhFw.glbAguPWPo0Hc6QUgJ" ascii //weight: 1
        $x_1_3 = "is tampered" ascii //weight: 1
        $x_1_4 = "Debugger Detected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Purelog_ABPG_2147975750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelog.ABPG!MTB"
        threat_id = "2147975750"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {26 20 00 00 00 00 38 95 fe ff ff 28 ?? 00 00 0a 72 0e 04 00 70 28 ?? 00 00 2b 28 ?? 00 00 2b 73 78 00 00 0a 18 17 8d ?? 00 00 01 25 16 28 ?? 00 00 06 20 00 84 01 00 28 ?? 00 00 06 28 ?? 00 00 2b a2}  //weight: 5, accuracy: Low
        $x_3_2 = {03 7c 42 00 00 04 28 ?? 00 00 0a 13 01 38 ?? 00 00 00 03 7b 41 00 00 04 39 ?? 00 00 00 38 ?? ff ff ff 03 7c 42 00 00 04 28 ?? 00 00 0a 13 01}  //weight: 3, accuracy: Low
        $x_2_3 = "GetPixel" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

