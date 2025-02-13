rule Trojan_Win32_SuspDeleteEventlog_A_2147794597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDeleteEventlog.A"
        threat_id = "2147794597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDeleteEventlog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "wevtutil.exe cl " wide //weight: 2
        $x_2_2 = "wevtutil cl " wide //weight: 2
        $x_2_3 = {77 00 65 00 76 00 74 00 75 00 74 00 69 00 6c 00 [0-80] 63 00 6c 00 65 00 61 00 72 00 2d 00 6c 00 6f 00 67 00}  //weight: 2, accuracy: Low
        $n_10_4 = "/Debug" wide //weight: -10
        $n_10_5 = "/Analytic" wide //weight: -10
        $n_10_6 = "/Diagnostic" wide //weight: -10
        $n_10_7 = "/Operational" wide //weight: -10
        $n_10_8 = "/Trace" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

