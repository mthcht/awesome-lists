rule Trojan_MSIL_SideWinder_A_2147773665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SideWinder.A!MTB"
        threat_id = "2147773665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SideWinder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 8e 69 1f 20 59 8d ?? ?? ?? ?? 0a 02 1f 20 06 16 06 8e 69 28 ?? ?? ?? ?? 16 0b 2b 16 06 07 8f 00 25 47 02 07 1f 20 5d 91 61 d2 52 07 17 58 0b 07 06 8e 69 32 e4 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

