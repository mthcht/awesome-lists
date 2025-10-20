rule Trojan_Win32_SuspSparrow_MK_2147955558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSparrow.MK"
        threat_id = "2147955558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSparrow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c " ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "update.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspSparrow_A_2147955559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSparrow.A"
        threat_id = "2147955559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSparrow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe export " ascii //weight: 1
        $x_1_2 = "HKCU\\Control Panel\\Desktop" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "screensaver.reg" ascii //weight: 1
        $x_1_5 = "/y" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspSparrow_B_2147955560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSparrow.B"
        threat_id = "2147955560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSparrow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add " ascii //weight: 1
        $x_1_2 = "HKCU\\Control Panel\\Desktop" ascii //weight: 1
        $x_1_3 = "/t REG_SZ /d" ascii //weight: 1
        $x_1_4 = "ScreenSaveActive" ascii //weight: 1
        $x_1_5 = "/v" wide //weight: 1
        $x_1_6 = "/f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspSparrow_C_2147955561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSparrow.C"
        threat_id = "2147955561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSparrow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /create /sc daily /tn" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "Microsoft\\Windows\\Power" ascii //weight: 1
        $x_1_4 = "/ST" wide //weight: 1
        $x_1_5 = "/tr" wide //weight: 1
        $x_1_6 = "/F" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

