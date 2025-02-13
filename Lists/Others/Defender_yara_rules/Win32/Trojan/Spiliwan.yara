rule Trojan_Win32_Spiliwan_A_2147637331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spiliwan.A"
        threat_id = "2147637331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spiliwan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xss3.htm" wide //weight: 1
        $x_1_2 = "iResearchiClick.exe" wide //weight: 1
        $x_1_3 = "id=hhhwei>" wide //weight: 1
        $x_1_4 = "?alexa=ture" wide //weight: 1
        $x_2_5 = "142#142#166#166#137#149#121#125#97#161#" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

