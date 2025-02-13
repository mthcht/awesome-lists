rule Trojan_MSIL_PowDownload_NEAA_2147839876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PowDownload.NEAA!MTB"
        threat_id = "2147839876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PowDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fe 0c 03 00 fe 0c 04 00 93 fe 0e 05 00 fe 0c 00 00 fe 0c 05 00 fe 09 02 00 59 d1 6f 0c 00 00 0a 26 fe 0c 04 00 20 01 00 00 00 58 fe 0e 04 00 fe 0c 04 00 fe 0c 03 00 8e 69 32 c5}  //weight: 10, accuracy: High
        $x_5_2 = "LILUZIVERT.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

