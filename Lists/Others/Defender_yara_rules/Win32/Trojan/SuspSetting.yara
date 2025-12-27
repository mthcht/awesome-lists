rule Trojan_Win32_SuspSetting_E_2147955604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSetting.E"
        threat_id = "2147955604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSetting"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c set" ascii //weight: 1
        $x_1_2 = "hostname.exe" ascii //weight: 1
        $x_1_3 = "qprocess" ascii //weight: 1
        $x_1_4 = "cmd.exe /c ver" ascii //weight: 1
        $x_1_5 = "cmd.exe /c systeminfo | findstr /B /C:OS Name /C:OS Version" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_SuspSetting_F_2147955605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSetting.F"
        threat_id = "2147955605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSetting"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WinSystemLocale" ascii //weight: 1
        $x_1_3 = "Select-Object" ascii //weight: 1
        $x_1_4 = "OEMCP" ascii //weight: 1
        $x_1_5 = "TextInfo.OemCodePage" ascii //weight: 1
        $x_1_6 = "TextInfo.AnsiCodePage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspSetting_G_2147955606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSetting.G"
        threat_id = "2147955606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSetting"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Unblock-File" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp\\enum_disk.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspSetting_H_2147955607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSetting.H"
        threat_id = "2147955607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSetting"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "New-Object" ascii //weight: 1
        $x_1_3 = "System.Threading.Mutex(" ascii //weight: 1
        $x_1_4 = "Dispose()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

