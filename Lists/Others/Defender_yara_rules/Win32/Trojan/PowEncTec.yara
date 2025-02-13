rule Trojan_Win32_PowEncTec_B_2147927566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowEncTec.B!MTB"
        threat_id = "2147927566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowEncTec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "[convert]::frombase64string" wide //weight: 1
        $x_1_3 = "hidden" wide //weight: 1
        $x_1_4 = "| iex" wide //weight: 1
        $n_100_5 = "http" wide //weight: -100
        $n_100_6 = "iwr" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

