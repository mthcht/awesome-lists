rule Trojan_MSIL_WshRat_AWS_2147902955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WshRat.AWS!MTB"
        threat_id = "2147902955"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WshRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 2b 52 06 6f ?? 00 00 0a 74 ?? 00 00 01 0b 7e ?? 00 00 04 07 6f ?? 01 00 0a 6f ?? 01 00 0a 0c 08 2c 19 7e ?? 00 00 04 07 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "WSHRat.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

