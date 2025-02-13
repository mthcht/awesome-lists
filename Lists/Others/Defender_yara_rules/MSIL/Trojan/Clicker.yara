rule Trojan_MSIL_Clicker_NWE_2147788127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Clicker.NWE!MTB"
        threat_id = "2147788127"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clicker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 02 00 00 00 26 16 00 02 28 2a 00 00 0a 02 28 ?? 03 00 06 02 16 28 2f 00 00 0a 02 28 2b 00 00 0a 28 cb 00 00 0a 6f cc 00 00 0a 6f 16 00 00 0a 20 62 12 01 00 28 ?? ?? 00 06 28 84 00 00 0a 28 cd 00 00 0a 02 02 fe 06 a7 02 00 [0-1] 73 33 00 00 0a 28 34 00 00 0a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "WindowsFormsApplication25.pdb" ascii //weight: 1
        $x_1_3 = "nsICookieManager" ascii //weight: 1
        $x_1_4 = "SHDocVw" ascii //weight: 1
        $x_1_5 = "IHTMLDocument" ascii //weight: 1
        $x_1_6 = "mshtml" ascii //weight: 1
        $x_1_7 = "IWebBrowser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Clicker_SPQE_2147894534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Clicker.SPQE!MTB"
        threat_id = "2147894534"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clicker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kheiotrj" ascii //weight: 1
        $x_1_2 = "Bsvqvd" ascii //weight: 1
        $x_1_3 = "Oikoherg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

