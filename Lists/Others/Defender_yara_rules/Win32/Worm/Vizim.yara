rule Worm_Win32_Vizim_A_2147596270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vizim.A"
        threat_id = "2147596270"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vizim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\legal notice viri\\Project1.vbp" wide //weight: 5
        $x_5_2 = "c:\\windows\\autorun.inf" ascii //weight: 5
        $x_2_3 = "DisableRegistryTools" wide //weight: 2
        $x_2_4 = "DisableTaskMgr" wide //weight: 2
        $x_1_5 = "\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_6 = "\\windows\\currentversion\\run" wide //weight: 1
        $x_1_7 = "\\Windows\\CurrentVersion\\Policies\\System" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

