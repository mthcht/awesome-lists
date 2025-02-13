rule Trojan_MSIL_Snoload_SK_2147898756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snoload.SK!MTB"
        threat_id = "2147898756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snoload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 19 00 00 0a 0b 07 72 01 00 00 70 6f 1a 00 00 0a 0a de 0a 07 2c 06 07 6f 1b 00 00 0a dc}  //weight: 2, accuracy: High
        $x_2_2 = "DownLoader.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

