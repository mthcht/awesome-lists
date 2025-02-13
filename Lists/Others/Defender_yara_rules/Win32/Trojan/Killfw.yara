rule Trojan_Win32_Killfw_A_2147628555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killfw.A"
        threat_id = "2147628555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killfw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg add \"HKLM\\software\\microsoft\\security center\" /v FirewallDisableNotify /t REG_DWORD /d 4 /f" ascii //weight: 1
        $x_1_2 = "reg add \"HKLM\\software\\microsoft\\security center\" /v UpdatesDisableNotify /t REG_DWORD /d 4 /f" ascii //weight: 1
        $x_1_3 = "call svshost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

