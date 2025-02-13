rule Trojan_MSIL_BlueFox_RDA_2147837815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BlueFox.RDA!MTB"
        threat_id = "2147837815"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlueFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fc1f81dad30" ascii //weight: 1
        $x_1_2 = "BlueFox" wide //weight: 1
        $x_1_3 = "set_UseShellExecute" ascii //weight: 1
        $x_1_4 = "d7aa80c9dcd" ascii //weight: 1
        $x_1_5 = "72b26e23ed4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

