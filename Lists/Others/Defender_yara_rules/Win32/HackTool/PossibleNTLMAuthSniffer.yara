rule HackTool_Win32_PossibleNTLMAuthSniffer_A_2147950480_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PossibleNTLMAuthSniffer.A"
        threat_id = "2147950480"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PossibleNTLMAuthSniffer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "System.Net.HttpListener" wide //weight: 10
        $x_10_3 = ".Prefixes.Add(" wide //weight: 10
        $x_10_4 = "0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x00,0x00," wide //weight: 10
        $x_1_5 = "0x00,0x00,0x00,0x28,0x00,0x00,0x01,0x82,0x00,0x00,0x11,0x22,0x33,0x44," wide //weight: 1
        $x_1_6 = "0x55,0x66,0x77,0x88,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

