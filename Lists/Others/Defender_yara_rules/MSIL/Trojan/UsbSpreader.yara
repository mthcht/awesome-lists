rule Trojan_MSIL_UsbSpreader_2147740441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/UsbSpreader"
        threat_id = "2147740441"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "UsbSpreader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Y2FwdHVyZQ==" wide //weight: 1
        $x_1_2 = "SGFuZGxlTGltZVVTQi5IYW5kbGVMaW1lVVNC" wide //weight: 1
        $x_1_3 = "dG9ycmVudA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

