rule Trojan_Win32_Coribakedow_A_2147767963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coribakedow.A"
        threat_id = "2147767963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coribakedow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Users\\Public\\reserve.exe" ascii //weight: 10
        $x_10_2 = "REG ADD \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /V \"microsoft update\" /t REG_SZ /F /D \"SCHTASKS /run /tn" ascii //weight: 10
        $x_1_3 = "microsoftestore.top" ascii //weight: 1
        $x_1_4 = "microsoftsystemcloud.com" ascii //weight: 1
        $x_1_5 = "chaseltd.top" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Coribakedow_A_2147767966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coribakedow.A!!Coribakedow.A"
        threat_id = "2147767966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coribakedow"
        severity = "Critical"
        info = "Coribakedow: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Users\\Public\\reserve.exe" ascii //weight: 10
        $x_10_2 = "REG ADD \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /V \"microsoft update\" /t REG_SZ /F /D \"SCHTASKS /run /tn" ascii //weight: 10
        $x_1_3 = "microsoftestore.top" ascii //weight: 1
        $x_1_4 = "microsoftsystemcloud.com" ascii //weight: 1
        $x_1_5 = "chaseltd.top" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

