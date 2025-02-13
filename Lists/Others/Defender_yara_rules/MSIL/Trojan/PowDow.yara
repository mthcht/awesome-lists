rule Trojan_MSIL_PowDow_NEAA_2147841114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PowDow.NEAA!MTB"
        threat_id = "2147841114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PowDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0d 09 06 6f 27 00 00 0a 00 09 18 6f 28 00 00 0a 00 09 18 6f 29 00 00 0a 00 09 6f 2a 00 00 0a 13 04 11 04 07 16 07 8e 69 6f 2b 00 00 0a 13 05 09}  //weight: 10, accuracy: High
        $x_5_2 = "Hide-PowerShell" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PowDow_NEAB_2147843931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PowDow.NEAB!MTB"
        threat_id = "2147843931"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PowDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 28 06 00 00 06 74 1e 00 00 01 72 51 00 00 70 20 00 01 00 00 14 14 14 6f 1b 00 00 0a 2a}  //weight: 10, accuracy: High
        $x_2_2 = "is tampered" wide //weight: 2
        $x_2_3 = "set_CreateNoWindow" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

