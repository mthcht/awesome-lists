rule Trojan_MSIL_BPLogger_AKXA_2147944422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BPLogger.AKXA!MTB"
        threat_id = "2147944422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BPLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 00 11 02 02 11 02 91 03 11 02 11 01 5d 6f ?? 00 00 0a 61 d2 9c 20}  //weight: 4, accuracy: Low
        $x_2_2 = {11 02 17 58 13 02 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

