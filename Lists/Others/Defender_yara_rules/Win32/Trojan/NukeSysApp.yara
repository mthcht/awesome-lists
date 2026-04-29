rule Trojan_Win32_NukeSysApp_2147968060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NukeSysApp"
        threat_id = "2147968060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NukeSysApp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell.exe" wide //weight: 2
        $x_14_2 = "appdata\\locallow\\windows sytem" wide //weight: 14
        $x_11_3 = "program rules\\program rules" wide //weight: 11
        $x_5_4 = "-windowstyle hidden" wide //weight: 5
        $x_6_5 = "-executionpolicy bypass" wide //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_14_*) and 1 of ($x_11_*) and 1 of ($x_5_*))) or
            ((1 of ($x_14_*) and 1 of ($x_11_*) and 1 of ($x_6_*))) or
            (all of ($x*))
        )
}

