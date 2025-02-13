rule Trojan_MSIL_PSDownload_ABS_2147849340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PSDownload.ABS!MTB"
        threat_id = "2147849340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PSDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b 39 8e 69 19 2c 1d 17 59 2b 33 2b 1c 0b 2b f0 06 07 91 0d 06 07 06 08 91 9c 1b 2c f7 06 08 09 9c 07 17 58 0b 08 17 59 0c 16 2d d4 07 08 32 e0 06 2a 0a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

