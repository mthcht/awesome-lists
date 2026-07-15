rule Trojan_Win32_ScreenLocker_AMTB_2147973591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ScreenLocker!AMTB"
        threat_id = "2147973591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ScreenLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[ > Enter authorization code ]" ascii //weight: 2
        $x_2_2 = "SECMOD v1.0" ascii //weight: 2
        $x_2_3 = "\\password.hash" ascii //weight: 2
        $x_2_4 = "\\password.salt" ascii //weight: 2
        $x_1_5 = "Esc: DISABLED" ascii //weight: 1
        $x_1_6 = "\" /sc onlogon /rl highest /f" ascii //weight: 1
        $n_100_7 = "Uninst.exe" ascii //weight: -100
        $n_100_8 = "Uninstaller.exe" ascii //weight: -100
        $n_100_9 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

