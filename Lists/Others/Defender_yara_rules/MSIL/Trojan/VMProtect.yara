rule Trojan_MSIL_VMProtect_GVA_2147947418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VMProtect.GVA!MTB"
        threat_id = "2147947418"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VMProtect"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 50 00 00 04 03 07 6a 58 e0 47 06 61 20 ff 00 00 00 5f 95 06 1e 64 61 0a 07 17 58 0b 07 6a 04 6e 3f da ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

