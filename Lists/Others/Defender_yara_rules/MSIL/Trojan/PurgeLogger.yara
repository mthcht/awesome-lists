rule Trojan_MSIL_PurgeLogger_GVA_2147960147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PurgeLogger.GVA!MTB"
        threat_id = "2147960147"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PurgeLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0d 6f ff 0d 00 06 13 17 11 0d 6f ff 0d 00 06 13 18 11 04 11 17 11 18 6f 5c 02 00 0a 11 16 17 58 13 16 11 16 11 0c 3f d4 ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

