rule Trojan_MSIL_VIPKeyLogger_ZBM_2147953933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeyLogger.ZBM!MTB"
        threat_id = "2147953933"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 07 0e 06 69 11 2e 1f 0d 5a 58 11 2f 1d 5a 58 61 13 30 00 02 11 2e 11 2f 6f ?? 00 00 0a 13 31 04 03 6f ?? 00 00 0a 59}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

