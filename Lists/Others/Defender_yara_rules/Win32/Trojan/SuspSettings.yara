rule Trojan_Win32_SuspSettings_E_2147954151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSettings.E"
        threat_id = "2147954151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSettings"
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
        $n_1_6 = "69802c98-2cm2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_SuspSettings_F_2147954152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSettings.F"
        threat_id = "2147954152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSettings"
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
        $n_1_7 = "69802c98-2cm2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspSettings_G_2147954153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSettings.G"
        threat_id = "2147954153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSettings"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Unblock-File" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp\\enum_disk.ps1" ascii //weight: 1
        $n_1_4 = "69802c98-2cn2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspSettings_H_2147954154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSettings.H"
        threat_id = "2147954154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSettings"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "New-Object" ascii //weight: 1
        $x_1_3 = "System.Threading.Mutex(" ascii //weight: 1
        $x_1_4 = "Dispose()" ascii //weight: 1
        $n_1_5 = "69802c98-2cm2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

