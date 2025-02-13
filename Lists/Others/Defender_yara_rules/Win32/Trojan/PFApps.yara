rule Trojan_Win32_PFApps_B_2147895804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PFApps.B"
        threat_id = "2147895804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PFApps"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" wide //weight: 1
        $x_1_2 = " -e " wide //weight: 1
        $x_1_3 = " -enc " wide //weight: 1
        $x_10_4 = "powershell.exe" wide //weight: 10
        $x_10_5 = "pwsh.exe" wide //weight: 10
        $n_1_6 = "[Guid]([Convert]::FromBase64String" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

