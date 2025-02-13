rule Trojan_Win64_Mabezat_RP_2147913651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mabezat.RP!MTB"
        threat_id = "2147913651"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mabezat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QtfiQngwfw~F" ascii //weight: 1
        $x_1_2 = "LjyUwthFiiwjxx" ascii //weight: 1
        $x_1_3 = "HwjfyjUnuj" ascii //weight: 1
        $x_1_4 = "UjjpSfrjiUnuj" ascii //weight: 1
        $x_1_5 = "HwjfyjUwthjxx\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

