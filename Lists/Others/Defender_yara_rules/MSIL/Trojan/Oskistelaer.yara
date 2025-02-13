rule Trojan_MSIL_Oskistelaer_AKI_2147832247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Oskistelaer.AKI!MTB"
        threat_id = "2147832247"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Oskistelaer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 74 34 00 00 01 0b 07 72 a7 00 00 70 6f}  //weight: 2, accuracy: High
        $x_1_2 = {0d 02 09 17 8d 05 00 00 01 13 06 11 06 16 72 57 00 00 70 a2 00 11 06 14 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

