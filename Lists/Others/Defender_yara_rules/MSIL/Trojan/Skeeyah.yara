rule Trojan_MSIL_Skeeyah_NS_2147925222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Skeeyah.NS!MTB"
        threat_id = "2147925222"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Skeeyah"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tqulizvnwwpcjrw.My.Resources" ascii //weight: 2
        $x_2_2 = "$657ba6d4-88a2-4fad-8eeb-23e1a547740a" ascii //weight: 2
        $x_2_3 = "casa 54" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

