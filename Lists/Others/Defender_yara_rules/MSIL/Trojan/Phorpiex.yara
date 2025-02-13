rule Trojan_MSIL_Phorpiex_2147741594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Phorpiex!MTB"
        threat_id = "2147741594"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0a 2b 0e 02 06 02 06 91 1f 1d 61 d2 9c 06 17 58 0a 06 02 8e 69 32 ec 02 2a}  //weight: 1, accuracy: High
        $x_1_2 = "YPEbchOPZXsx6QtWKuIZvIRWtGPU4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

