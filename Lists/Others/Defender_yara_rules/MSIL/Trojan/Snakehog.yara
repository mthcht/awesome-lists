rule Trojan_MSIL_Snakehog_MBFO_2147899003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakehog.MBFO!MTB"
        threat_id = "2147899003"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakehog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 04 08 8e 69 17 da 13 06 16 13 05 2b 21 11 04 08 11 05 8f 6e 00 00 01 28 d5 01}  //weight: 1, accuracy: High
        $x_1_2 = "lfwhUWZlmFnGhDYPudAJ.Resources.resource" ascii //weight: 1
        $x_1_3 = "de4fuckyou" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

