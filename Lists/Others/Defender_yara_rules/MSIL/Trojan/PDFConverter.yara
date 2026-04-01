rule Trojan_MSIL_PDFConverter_MX_2147966101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PDFConverter.MX!MTB"
        threat_id = "2147966101"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PDFConverter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NotAWord.exe" wide //weight: 1
        $x_1_2 = "moc.mimitosp.pan" ascii //weight: 1
        $x_1_3 = "psotimim.com" ascii //weight: 1
        $x_1_4 = "CSIRELSCSIRELS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

