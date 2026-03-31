rule Trojan_Win32_LummaS_B_2147965929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaS.B"
        threat_id = "2147965929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--processStart=\"pythonw.exe\"" wide //weight: 1
        $x_1_2 = "--process-start-args=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

