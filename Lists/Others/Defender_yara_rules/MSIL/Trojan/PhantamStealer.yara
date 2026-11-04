rule Trojan_MSIL_PhantamStealer_MZG_2147981399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantamStealer.MZG!MTB"
        threat_id = "2147981399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantamStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 66 69 67 00 67 65 74 5f 41 6c 6c 6f 77 4f 6e 6c 79 46 69 70 73 41 6c 67 6f 72 69 74 68 6d 73 00 73 62 63 65 4d 6b 32 43 63 57 00 4d 44 35 43 72 79 70 74 6f 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

