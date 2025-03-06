rule Trojan_MSIL_Tepfer_AGNA_2147935313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tepfer.AGNA!MTB"
        threat_id = "2147935313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 1f 0c 5d 09 1f 2c 5d 58 20 8d 03 00 00 09 1f 23 5d 20 d3 00 00 00 58 5a 58 13 04 06 09 6f ?? 00 00 0a 11 04 59 d1 13 05 07 11 05 6f ?? 00 00 0a 26 09 17 58 0d 09 06 6f ?? 00 00 0a 32 c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

