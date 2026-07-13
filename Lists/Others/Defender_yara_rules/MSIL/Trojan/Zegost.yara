rule Trojan_MSIL_Zegost_GVN_2147973437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zegost.GVN!MTB"
        threat_id = "2147973437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "net48\\WUUpdate.pdb" ascii //weight: 15
        $x_15_2 = "net48\\RatClient.pdb" ascii //weight: 15
        $x_10_3 = "CommandExecutor" ascii //weight: 10
        $x_10_4 = "ProcPull" ascii //weight: 10
        $x_10_5 = "RelayManager" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 3 of ($x_10_*))) or
            ((2 of ($x_15_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

