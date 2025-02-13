rule Trojan_MSIL_bulz_KA_2147850831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/bulz.KA!MTB"
        threat_id = "2147850831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {08 09 02 09 6f 19 00 00 0a 03 09 07 5d 6f 19 00 00 0a 61 d1 9d 09 17 58 0d 09 06 32 e3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

