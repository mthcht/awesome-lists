rule Trojan_Win32_BeaverTail_ARA_2147930777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BeaverTail.ARA!MTB"
        threat_id = "2147930777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BeaverTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "curl" wide //weight: 2
        $x_2_2 = "python" wide //weight: 2
        $x_10_3 = "\\.n2/pay" wide //weight: 10
        $x_10_4 = "\\.n2/bow" wide //weight: 10
        $x_10_5 = "/pdown" wide //weight: 10
        $x_10_6 = "\\.npl" wide //weight: 10
        $x_10_7 = "/.n2/pay" wide //weight: 10
        $x_10_8 = "/.n2/bow" wide //weight: 10
        $x_10_9 = "/.npl" wide //weight: 10
        $x_10_10 = "/.sysinfo" wide //weight: 10
        $x_10_11 = "\\.n2/mlip" wide //weight: 10
        $x_10_12 = "/.n2/mlip" wide //weight: 10
        $n_100_13 = "sentinel" wide //weight: -100
        $n_100_14 = "sysinfo.h" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

