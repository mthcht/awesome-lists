rule Trojan_Win32_SuspProcFromPossibleRenPyExec_EA_2147970762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProcFromPossibleRenPyExec.EA"
        threat_id = "2147970762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProcFromPossibleRenPyExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "forfiles" wide //weight: 10
        $x_10_2 = " /p " wide //weight: 10
        $x_10_3 = " /m " wide //weight: 10
        $x_1_4 = ".bat" wide //weight: 1
        $x_1_5 = ".cmd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

