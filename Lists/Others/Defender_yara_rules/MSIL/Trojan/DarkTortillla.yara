rule Trojan_MSIL_DarkTortillla_GKV_2147958715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortillla.GKV!MTB"
        threat_id = "2147958715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortillla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 8e 69 17 da 0d 16 13 04 2b 15 07 11 04 07 11 04 91 20 bb 00 00 00 61 b4 9c 11 04 1b d6 13 04 11 04 09 31 e6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

