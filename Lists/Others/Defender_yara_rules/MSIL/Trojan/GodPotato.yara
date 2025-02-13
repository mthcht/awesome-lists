rule Trojan_MSIL_GodPotato_FF_2147848417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GodPotato.FF!MTB"
        threat_id = "2147848417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GodPotato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "18f70770-8e64-11cf-9af1-0020af6e72f4" wide //weight: 1
        $x_1_2 = "[\\pipe\\epmapper]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

