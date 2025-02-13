rule Trojan_Win32_MpTamperPsExec_A_2147783906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperPsExec.A"
        threat_id = "2147783906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperPsExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "Set-MpPreference" wide //weight: 1
        $x_1_3 = "-DisableRealtimeMonitoring" wide //weight: 1
        $x_1_4 = "New-Object" wide //weight: 1
        $x_1_5 = "Net.Webclient" wide //weight: 1
        $x_1_6 = ".downloadstring" wide //weight: 1
        $n_5_7 = {2d 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 72 00 65 00 61 00 6c 00 74 00 69 00 6d 00 65 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 20 00 [0-2] 66 00 61 00 6c 00 73 00 65 00}  //weight: -5, accuracy: Low
        $n_5_8 = "-DisableRealtimeMonitoring 0" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_MpTamperPsExec_B_2147783907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperPsExec.B"
        threat_id = "2147783907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperPsExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "Set-MpPreference" wide //weight: 2
        $x_2_3 = "-DisableRealtimeMonitoring" wide //weight: 2
        $x_2_4 = "-enc" wide //weight: 2
        $x_1_5 = "bypass" wide //weight: 1
        $x_1_6 = "hidden" wide //weight: 1
        $n_5_7 = {2d 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 72 00 65 00 61 00 6c 00 74 00 69 00 6d 00 65 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 20 00 [0-2] 66 00 61 00 6c 00 73 00 65 00}  //weight: -5, accuracy: Low
        $n_5_8 = "-DisableRealtimeMonitoring 0" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperPsExec_C_2147783908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperPsExec.C"
        threat_id = "2147783908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperPsExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "Set-MpPreference" wide //weight: 1
        $x_1_3 = "-DisableRealtimeMonitoring" wide //weight: 1
        $x_1_4 = "IEX" wide //weight: 1
        $n_5_5 = {2d 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 72 00 65 00 61 00 6c 00 74 00 69 00 6d 00 65 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 20 00 [0-2] 66 00 61 00 6c 00 73 00 65 00}  //weight: -5, accuracy: Low
        $n_5_6 = "-DisableRealtimeMonitoring 0" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

