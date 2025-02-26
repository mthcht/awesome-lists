rule Trojan_Win32_SuspPowershellXmlDownload_ZPA_2147934573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspPowershellXmlDownload.ZPA"
        threat_id = "2147934573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowershellXmlDownload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "-exec bypass" wide //weight: 10
        $x_10_3 = "New-Object System.Xml.XmlDocument" wide //weight: 10
        $x_10_4 = ".load" wide //weight: 10
        $x_10_5 = ".execute" wide //weight: 10
        $x_1_6 = ";IEX" wide //weight: 1
        $x_1_7 = "IEX " wide //weight: 1
        $x_1_8 = "IEX(" wide //weight: 1
        $x_1_9 = "|IEX" wide //weight: 1
        $x_1_10 = "| IEX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

