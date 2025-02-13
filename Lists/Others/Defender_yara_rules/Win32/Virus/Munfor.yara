rule Virus_Win32_Munfor_B_2147601326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Munfor.B"
        threat_id = "2147601326"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Munfor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Office\\8.0\\New User Settings\\PowerPoint\\Options\\MacroVirusProtection" wide //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools" wide //weight: 1
        $x_1_3 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows Scripting Host\\Settings\\Timeout" wide //weight: 1
        $x_1_4 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\W32Load" wide //weight: 1
        $x_1_5 = "C:\\WINDOWS\\Escritorio\\Multi-Infect\\Multi-Infect.vbp" wide //weight: 1
        $x_1_6 = "Application.Worksheets(1).Shapes(1).OLEFormat.Activate" wide //weight: 1
        $x_1_7 = "\\Multi-Infector.pif" wide //weight: 1
        $x_1_8 = "\\Multi-Infect.dll" wide //weight: 1
        $x_1_9 = "\\Template.xls.scr" wide //weight: 1
        $x_1_10 = "Multi-Infect.exe" wide //weight: 1
        $x_1_11 = "DocInfected" ascii //weight: 1
        $x_1_12 = "ZipInfected" ascii //weight: 1
        $x_1_13 = "PptInfected" ascii //weight: 1
        $x_1_14 = "RarInfected" ascii //weight: 1
        $x_1_15 = "ExeInfected" ascii //weight: 1
        $x_1_16 = "</Script>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (14 of ($x*))
}

