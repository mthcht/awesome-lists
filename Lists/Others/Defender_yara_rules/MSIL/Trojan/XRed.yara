rule Trojan_MSIL_XRed_AXR_2147962465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XRed.AXR!MTB"
        threat_id = "2147962465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XRed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 11 04 72 ?? 00 00 70 6f ?? 00 00 0a 2d 0e 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 13 04 11 04 09 20 10 27 00 00 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 13 04 02 03 11 04 28 ?? 00 00 06 28 ?? 00 00 0a 13 05 11 05 72 ?? 00 00 70 6f ?? 00 00 0a 2d 0e 11 05 72 ?? 00 00 70 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

