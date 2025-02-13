rule Trojan_MSIL_SilkStealer_A_2147844268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SilkStealer.A!MTB"
        threat_id = "2147844268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SilkStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Silk.pdb" ascii //weight: 2
        $x_2_2 = "MozGlueNotFound" ascii //weight: 2
        $x_2_3 = "Nss3CouldNotBeLoaded" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

