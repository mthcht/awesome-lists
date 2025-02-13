rule Trojan_MSIL_Ramcos_RDA_2147834347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ramcos.RDA!MTB"
        threat_id = "2147834347"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ramcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "192.227.183.152" wide //weight: 1
        $x_2_2 = {06 6f 2d 00 00 0a 0b 07 d2 13 07 12 07 72 ?? ?? ?? ?? 28 2e 00 00 0a 13 04 11 06 07 11 04 a2 08 11 04 07 d2 6f 2f 00 00 0a 08 11 04 6f 30 00 00 0a 07 d2 6f 2f 00 00 0a 06 6f 31 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ramcos_RDB_2147837538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ramcos.RDB!MTB"
        threat_id = "2147837538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ramcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 10 11 2f 11 1f 59 61 13 10 11 1f 19 11 10 58 1e 63 59 13}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualMemSim" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ramcos_RDC_2147838556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ramcos.RDC!MTB"
        threat_id = "2147838556"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ramcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tgsedmalkjzmtryv" ascii //weight: 1
        $x_1_2 = "eaff211aef96417ac067f85cf0fa98a3" wide //weight: 1
        $x_1_3 = "ncrypt" ascii //weight: 1
        $x_1_4 = "kernel32" ascii //weight: 1
        $x_1_5 = "NCryptEncrypt" ascii //weight: 1
        $x_1_6 = "VirtualProtectEx" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

