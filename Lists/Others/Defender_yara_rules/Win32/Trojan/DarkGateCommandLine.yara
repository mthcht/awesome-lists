rule Trojan_Win32_DarkGateCommandLine_AB_2147893444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkGateCommandLine.AB!cmd"
        threat_id = "2147893444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkGateCommandLine"
        severity = "Critical"
        info = "cmd: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "curl" wide //weight: 1
        $x_1_3 = "Autoit3.exe" wide //weight: 1
        $x_1_4 = "http://" wide //weight: 1
        $x_1_5 = ".au3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

