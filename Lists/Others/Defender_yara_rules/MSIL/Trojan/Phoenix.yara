rule Trojan_MSIL_Phoenix_ABRG_2147845885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Phoenix.ABRG!MTB"
        threat_id = "2147845885"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phoenix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? 00 00 0a 11 04 17 25 2c 07 58 13 04 11 04 07 8e 69 32 dc 06 09 6f ?? 00 00 0a 6f ?? 00 00 0a de 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

