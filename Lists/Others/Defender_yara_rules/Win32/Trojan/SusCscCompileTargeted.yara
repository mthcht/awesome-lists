rule Trojan_Win32_SusCscCompileTargeted_MK_2147970490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusCscCompileTargeted.MK"
        threat_id = "2147970490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusCscCompileTargeted"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "csc.exe" wide //weight: 1
        $x_1_2 = "/target:" wide //weight: 1
        $x_1_3 = ".cs" wide //weight: 1
        $n_1_4 = "m4896cf8-a4fa-40e9-90e0-3b2ddc3e3ceu" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

