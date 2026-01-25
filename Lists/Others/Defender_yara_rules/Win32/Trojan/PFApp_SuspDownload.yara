rule Trojan_Win32_PFApp_SuspDownload_A_2147961702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PFApp_SuspDownload.A"
        threat_id = "2147961702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PFApp_SuspDownload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "downloadstring" wide //weight: 1
        $x_1_2 = "downloadfile(" wide //weight: 1
        $x_5_3 = "invoke-expression" wide //weight: 5
        $x_5_4 = "iex " wide //weight: 5
        $x_5_5 = "iex(" wide //weight: 5
        $x_10_6 = "powershell.exe" wide //weight: 10
        $x_10_7 = "pwsh.exe" wide //weight: 10
        $x_10_8 = "cmd.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

