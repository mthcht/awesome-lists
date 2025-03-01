rule Trojan_MSIL_disco_RDA_2147894435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/disco.RDA!MTB"
        threat_id = "2147894435"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cbfc808d-c1b6-4605-9f10-10ad318470be" ascii //weight: 1
        $x_1_2 = "NetTrack" ascii //weight: 1
        $x_1_3 = "SystemInfoApp" ascii //weight: 1
        $x_1_4 = "IsUserAdministrator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

