rule Trojan_Win32_ClearEventLogViaPowerShell_A_2147949598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClearEventLogViaPowerShell.A"
        threat_id = "2147949598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearEventLogViaPowerShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "powershell.exe clear-eventlog -logname attackiq_" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

