rule Trojan_MSIL_GurcuStealer_A_2147845817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GurcuStealer.A!MTB"
        threat_id = "2147845817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GurcuStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe 0c 01 00 fe 09 00 00 fe 0c ?? 00 6f ?? 00 00 0a fe 0c 00 00 fe 0c ?? 00 fe 0c 00 00 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d1 fe 0e ?? 00 fe 0d ?? 00 28 ?? 00 00 0a 28 ?? 00 00 0a fe 0e 01 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_GurcuStealer_AAFT_2147851344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GurcuStealer.AAFT!MTB"
        threat_id = "2147851344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GurcuStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_gZhD9cAiSBw2p.Properties.Resources.resources" ascii //weight: 1
        $x_1_2 = "234sdf" ascii //weight: 1
        $x_1_3 = "423sdfq121" ascii //weight: 1
        $x_1_4 = "esrf3wr" ascii //weight: 1
        $x_1_5 = "520b81d4-b03a-4bfa-a77f-195e662a28b6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

