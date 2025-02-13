rule Trojan_MSIL_Elmb_A_2147723623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Elmb.A!bit"
        threat_id = "2147723623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Elmb"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 6c 65 65 70 00 67 65 74 5f 49 73 41 6c 69 76 65 00 45 6c 6d 30 44}  //weight: 1, accuracy: High
        $x_1_2 = "TertiaryInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

