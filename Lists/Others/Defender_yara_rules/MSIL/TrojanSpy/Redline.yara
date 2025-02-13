rule TrojanSpy_MSIL_Redline_STA_2147786292_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Redline.STA"
        threat_id = "2147786292"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redline"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%USRCARCAERPRCARCAROFRCARCAILE%" wide //weight: 1
        $x_1_2 = "ApRCApDRCAata\\RoaRCAming" wide //weight: 1
        $x_1_3 = "FAASD.FAASDscFAASDr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

