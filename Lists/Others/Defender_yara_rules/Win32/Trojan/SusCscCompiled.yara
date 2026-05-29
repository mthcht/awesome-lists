rule Trojan_Win32_SusCscCompiled_MK_2147970489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusCscCompiled.MK"
        threat_id = "2147970489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusCscCompiled"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "csc.exe" wide //weight: 1
        $x_1_2 = "/out:" wide //weight: 1
        $x_1_3 = ".exe" wide //weight: 1
        $x_1_4 = ".cs" wide //weight: 1
        $n_1_5 = "k4896cf8-a4fa-40e9-90e0-3b2ddc3e3cy3" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

