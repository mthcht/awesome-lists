rule Trojan_O97M_Kerdown_A_2147735748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Kerdown.A"
        threat_id = "2147735748"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Kerdown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wsh.Run \"cmd.exe /S /C reg add  HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\ /f /reg:64\", windowStyle, waitOnReturn" ascii //weight: 1
        $x_1_2 = "wsh.Run \"cmd.exe /S /C reg add  HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{2DEA658F-54C1-4227-AF9B-260AB5FC3543} /f /reg:64\", windowStyle, waitOnReturn" ascii //weight: 1
        $x_1_3 = "wsh.Run \"cmd.exe /S /C reg add  HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}\\InprocServer32 /ve /t REG_SZ /d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Kerdown_B_2147735751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Kerdown.B"
        threat_id = "2147735751"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Kerdown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wsh.Run \"cmd.exe /S /C reg add  HKEY_CURRENT_USER\\" ascii //weight: 10
        $x_10_2 = "If RegKeyExists(\"HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{2DEA658F-54C1-4227-AF9B-260AB5FC3543}\\InprocServer32\\\")" ascii //weight: 10
        $x_1_3 = "\\main_background.png" ascii //weight: 1
        $x_1_4 = "\\SecurityAndMaintenance_Error.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_Kerdown_C_2147735752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Kerdown.C"
        threat_id = "2147735752"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Kerdown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\main_background.png" ascii //weight: 1
        $x_1_2 = "\\SecurityAndMaintenance_Error.png" ascii //weight: 1
        $x_1_3 = "\\WinwordUpdates.exe" ascii //weight: 1
        $x_1_4 = "& \"\\wwlib.dll\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_O97M_Kerdown_D_2147735753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Kerdown.D"
        threat_id = "2147735753"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Kerdown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " & \"\\msohtml.exe\"" ascii //weight: 1
        $x_1_2 = " & \" //E:vbscript /b \" & " ascii //weight: 1
        $x_1_3 = " & \"\\msohtml.log\"" ascii //weight: 1
        $x_1_4 = "= \"HKCU\\Software\\Classes\\CLSID\\{\"" ascii //weight: 1
        $x_1_5 = "& \"}\\Shell\\Manage\\Command\\\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

