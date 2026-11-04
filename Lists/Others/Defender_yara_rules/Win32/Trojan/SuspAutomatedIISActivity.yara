rule Trojan_Win32_SuspAutomatedIISActivity_A_2147981512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspAutomatedIISActivity.A"
        threat_id = "2147981512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspAutomatedIISActivity"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\cmd.exe" wide //weight: 10
        $x_10_2 = "/c " wide //weight: 10
        $x_5_3 = "echo ===" wide //weight: 5
        $x_5_4 = "echo ---" wide //weight: 5
        $n_50_5 = "chcp " wide //weight: -50
        $n_50_6 = "/x/d/c" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

