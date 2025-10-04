rule Trojan_Win32_Wromup_SA_2147954021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wromup.SA"
        threat_id = "2147954021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wromup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "/WMRX:F0E" wide //weight: 1
        $x_1_3 = "/WFXI:BNYE5S" wide //weight: 1
        $x_1_4 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

