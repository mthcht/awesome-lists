rule Trojan_MSIL_CrypterX_RDA_2147851700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrypterX.RDA!MTB"
        threat_id = "2147851700"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrypterX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9c0f7060-3b6a-495e-a82a-4ed09cb98e48" ascii //weight: 1
        $x_1_2 = "DataProtectionScope" ascii //weight: 1
        $x_1_3 = "father" ascii //weight: 1
        $x_1_4 = "ProtectMe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

