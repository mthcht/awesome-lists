rule Trojan_MSIL_DeerStealer_AMTB_2147972463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DeerStealer!AMTB"
        threat_id = "2147972463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DeerStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "**WeeStealer Tree:**" ascii //weight: 1
        $x_1_2 = "WeeStealer Output" ascii //weight: 1
        $x_1_3 = "\\Desktop\\src_New\\obj\\Release\\net8.0-windows\\wees.pdb" ascii //weight: 1
        $x_1_4 = "ExportCreditCards" ascii //weight: 1
        $x_1_5 = "ChromeAppBoundDecrypter.Payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

