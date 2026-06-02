rule Trojan_Win32_SuspProcFromRenPyExec_EA_2147970761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProcFromRenPyExec.EA"
        threat_id = "2147970761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProcFromRenPyExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 00 66 00 6f 00 72 00 66 00 69 00 6c 00 65 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
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

