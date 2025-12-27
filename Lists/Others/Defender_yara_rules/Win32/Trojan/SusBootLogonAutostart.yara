rule Trojan_Win32_SusBootLogonAutostart_A_2147958180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusBootLogonAutostart.A"
        threat_id = "2147958180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusBootLogonAutostart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "Applications\\Microsoft" ascii //weight: 1
        $x_1_4 = "/t REG_EXPAND_SZ /v" ascii //weight: 1
        $x_1_5 = "wsktray.exe" ascii //weight: 1
        $x_1_6 = " /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusBootLogonAutostart_B_2147958182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusBootLogonAutostart.B"
        threat_id = "2147958182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusBootLogonAutostart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = ".exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusBootLogonAutostart_D_2147958185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusBootLogonAutostart.D"
        threat_id = "2147958185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusBootLogonAutostart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = ".txt" wide //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "=type" wide //weight: 1
        $x_1_5 = "New-Item -Force -ItemType SymbolicLink -Path" ascii //weight: 1
        $x_1_6 = "-Value" wide //weight: 1
        $x_1_7 = "-Name" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_SusBootLogonAutostart_E_2147958186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusBootLogonAutostart.E"
        threat_id = "2147958186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusBootLogonAutostart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "AppData\\Roaming" ascii //weight: 1
        $x_1_3 = "Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii //weight: 1
        $x_1_4 = "New-Item -Force -ItemType SymbolicLink -Path" ascii //weight: 1
        $x_1_5 = "-Value" wide //weight: 1
        $x_1_6 = "-Name" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_SusBootLogonAutostart_F_2147958187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusBootLogonAutostart.F"
        threat_id = "2147958187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusBootLogonAutostart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "AppData\\Roaming" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "New-Item -Force -ItemType SymbolicLink -Path" ascii //weight: 1
        $x_1_5 = "-Value" wide //weight: 1
        $x_1_6 = "-Name" wide //weight: 1
        $x_1_7 = "=type" wide //weight: 1
        $x_1_8 = ":APPDATA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_SusBootLogonAutostart_G_2147958188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusBootLogonAutostart.G"
        threat_id = "2147958188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusBootLogonAutostart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "/t REG_SZ /F /D" ascii //weight: 1
        $x_1_4 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_5 = ".txt" wide //weight: 1
        $x_1_6 = " /V" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusBootLogonAutostart_H_2147958189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusBootLogonAutostart.H"
        threat_id = "2147958189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusBootLogonAutostart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c echo" ascii //weight: 1
        $x_1_2 = " > " wide //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = ".txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusBootLogonAutostart_M_2147958192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusBootLogonAutostart.M"
        threat_id = "2147958192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusBootLogonAutostart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "/t REG_DWORD /d" ascii //weight: 1
        $x_1_3 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_4 = " /v" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

