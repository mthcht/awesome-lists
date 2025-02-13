rule Trojan_MSIL_Renerez_AKV_2147752803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Renerez.AKV!MTB"
        threat_id = "2147752803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Renerez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mscorjit.dll" ascii //weight: 1
        $x_1_2 = "Freemake Products Keygen by Go2Crck@Team.exe" wide //weight: 1
        $x_1_3 = "Go2Crck@Team" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

