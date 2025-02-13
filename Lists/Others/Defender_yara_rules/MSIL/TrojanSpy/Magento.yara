rule TrojanSpy_MSIL_Magento_A_2147727032_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Magento.A!bit"
        threat_id = "2147727032"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Magento"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://terrigohesh.com/adminka3" wide //weight: 1
        $x_1_2 = "new_g.php?hwid=" wide //weight: 1
        $x_1_3 = "magento" wide //weight: 1
        $x_1_4 = "opencard" wide //weight: 1
        $x_1_5 = "&dummy=&login[password]=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

