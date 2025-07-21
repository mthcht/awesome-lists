rule Trojan_Win32_PShellDown_SC_2147942141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDown.SC"
        threat_id = "2147942141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" ascii //weight: 10
        $x_10_2 = "http" ascii //weight: 10
        $x_10_3 = "net-webclient" ascii //weight: 10
        $x_20_4 = "microsoft.powershell.commands.webrequestsession" ascii //weight: 20
        $x_10_5 = "invoke-webrequest" ascii //weight: 10
        $x_1_6 = "downloadstring" ascii //weight: 1
        $x_1_7 = "downloadfile" ascii //weight: 1
        $x_1_8 = "invoke-expression" ascii //weight: 1
        $x_1_9 = "iex " ascii //weight: 1
        $n_500_10 = "function checkscript" wide //weight: -500
        $n_100_11 = "https://dev-shell.gaiacloud.jpmchase.net/api/install/v1" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

