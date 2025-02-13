rule Trojan_MSIL_MultiRAT_RDA_2147900578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MultiRAT.RDA!MTB"
        threat_id = "2147900578"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MultiRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 28 01 00 00 2b 28 02 00 00 2b 28 27 01 00 0a 6f 28 01 00 0a 28 03 00 00 2b 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

