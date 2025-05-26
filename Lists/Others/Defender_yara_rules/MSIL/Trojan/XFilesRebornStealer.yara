rule Trojan_MSIL_XFilesRebornStealer_AXR_2147942227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XFilesRebornStealer.AXR!MTB"
        threat_id = "2147942227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XFilesRebornStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 09 2b 3e 11 08 11 09 9a 13 0a 00 11 0a 6f ?? 00 00 0a 72 ?? 05 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 2d 03 17 2b 01 16 13 0b 11 0a 6f}  //weight: 2, accuracy: Low
        $x_3_2 = "xfilesreborn.ru" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

