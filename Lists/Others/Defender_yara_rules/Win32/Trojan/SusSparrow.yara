rule Trojan_Win32_SusSparrow_MK_2147954093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusSparrow.MK"
        threat_id = "2147954093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusSparrow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c " ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "update.bat" ascii //weight: 1
        $n_1_4 = "a453e881-26a8-4973-bc2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusSparrow_A_2147954094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusSparrow.A"
        threat_id = "2147954094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusSparrow"
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
        $n_1_6 = "a453e881-26a8-4973-bd2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusSparrow_B_2147954095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusSparrow.B"
        threat_id = "2147954095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusSparrow"
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
        $n_1_7 = "a453e881-26a8-4973-be2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusSparrow_C_2147954096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusSparrow.C"
        threat_id = "2147954096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusSparrow"
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
        $n_1_7 = "a453e881-26a8-4973-bf2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

