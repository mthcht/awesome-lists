rule Backdoor_Win32_Coolvidoor_A_2147601105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coolvidoor.A"
        threat_id = "2147601105"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coolvidoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1b 06 45 53 43 41 50 45}  //weight: 1, accuracy: High
        $x_1_2 = {43 41 50 53 4c 4f 43 4b 00}  //weight: 1, accuracy: High
        $x_1_3 = {09 42 41 43 4b 53 50 41 43 45}  //weight: 1, accuracy: High
        $x_1_4 = "jpgcool." ascii //weight: 1
        $x_1_5 = "MSG|No se pudo eliminar la clave o el valor." ascii //weight: 1
        $x_1_6 = "MSG|Clave o Valor eliminado con" ascii //weight: 1
        $x_1_7 = "LISTARVALORES|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Coolvidoor_B_2147601207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coolvidoor.B"
        threat_id = "2147601207"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coolvidoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSG|Unidad no accesible!" ascii //weight: 1
        $x_1_2 = "MSG|El directorio no existe!" ascii //weight: 1
        $x_1_3 = "Symantec/Norton" ascii //weight: 1
        $x_1_4 = "PC-cillin Antivirus" ascii //weight: 1
        $x_1_5 = "F-Secure" ascii //weight: 1
        $x_1_6 = "avp.exe" ascii //weight: 1
        $x_1_7 = "MOUSETEMBLOROSO" ascii //weight: 1
        $x_1_8 = "CONGELARMOUSE" ascii //weight: 1
        $x_1_9 = "MATARBOTONINICIO|ACTIVADO" ascii //weight: 1
        $x_1_10 = "MATARBOTONINICIO|DESACTIVADO" ascii //weight: 1
        $x_1_11 = "LISTARVALORES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Backdoor_Win32_Coolvidoor_A_2147601249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coolvidoor.gen!A"
        threat_id = "2147601249"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coolvidoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\" ascii //weight: 1
        $x_1_2 = "ChangeServiceConfig2A" ascii //weight: 1
        $x_1_3 = "qmgr.dll" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\BITS\\Parameters" ascii //weight: 1
        $x_1_5 = "Shell_TrayWnd" ascii //weight: 1
        $x_1_6 = "log.log" ascii //weight: 1
        $x_1_7 = "WSAStartup" ascii //weight: 1
        $x_1_8 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\" ascii //weight: 1
        $x_1_9 = "WinXpMemory" ascii //weight: 1
        $x_1_10 = "Coolvibes" ascii //weight: 1
        $x_1_11 = "Windows XP" ascii //weight: 1
        $x_1_12 = "MSG|Unidad no accesible!" ascii //weight: 1
        $x_1_13 = "avp.exe" ascii //weight: 1
        $x_1_14 = "nod32krn.exe" ascii //weight: 1
        $x_1_15 = "BitDefender" ascii //weight: 1
        $x_1_16 = "Dr.Web" ascii //weight: 1
        $x_1_17 = "McAfee Personal Firewall" ascii //weight: 1
        $x_1_18 = "winsta0" ascii //weight: 1
        $x_1_19 = "Desconocido" ascii //weight: 1
        $x_1_20 = "OPENURL" ascii //weight: 1
        $x_1_21 = "CAPSCREEN" ascii //weight: 1
        $x_1_22 = "HKEY_CURRENT_CONFIG" ascii //weight: 1
        $x_1_23 = "RESUMETRANSFER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Coolvidoor_D_2147608547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coolvidoor.D"
        threat_id = "2147608547"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coolvidoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "cool.dat" ascii //weight: 3
        $x_3_2 = {43 6f 6f 6c [0-3] 73 65 72 76 65 72}  //weight: 3, accuracy: Low
        $x_3_3 = "GETFILE|" ascii //weight: 3
        $x_3_4 = "CAPTURAWEBCAM" ascii //weight: 3
        $x_3_5 = "CLICKIZQ" ascii //weight: 3
        $x_3_6 = "LISTARWEBCAMS|" ascii //weight: 3
        $x_3_7 = "SERVICIOSWIN|" ascii //weight: 3
        $x_3_8 = "\\melt" ascii //weight: 3
        $x_1_9 = "BACKSPACE" ascii //weight: 1
        $x_1_10 = "CAPSLOCK" ascii //weight: 1
        $x_1_11 = "SCROLLLOCK" ascii //weight: 1
        $x_7_12 = {3c 47 45 54 46 49 4c 45 53 3e [0-12] 3c 4c 49 53 54 4f 46 46 49 4c 45 53 3e [0-12] 4c 49 53 54 41 52 53 45 52 56 49 43 49 4f 53}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((5 of ($x_3_*))) or
            ((1 of ($x_7_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_7_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Coolvidoor_F_2147653960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coolvidoor.F"
        threat_id = "2147653960"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coolvidoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "coolvibes" ascii //weight: 2
        $x_2_2 = {43 6f 6f 6c [0-3] 73 65 72 76 65 72}  //weight: 2, accuracy: Low
        $x_1_3 = "MSG|Unidad no accesible!" ascii //weight: 1
        $x_1_4 = "GETFILE|" ascii //weight: 1
        $x_1_5 = "SERVIDOR|INFO|" ascii //weight: 1
        $x_1_6 = "VERUNIDADES|" ascii //weight: 1
        $x_1_7 = "LISTARARCHIVOS|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Coolvidoor_G_2147659041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coolvidoor.G"
        threat_id = "2147659041"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coolvidoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ACTION HAS STARTED AT:" ascii //weight: 1
        $x_1_2 = "System overloaded Now it will be burn" ascii //weight: 1
        $x_1_3 = "MSG|Drive not accessible!" ascii //weight: 1
        $x_1_4 = "-GOCHAT|" ascii //weight: 1
        $x_1_5 = "System Halted FFFFFF haha" ascii //weight: 1
        $x_1_6 = "[Print Screen]" ascii //weight: 1
        $x_1_7 = "Jaka_Kamu_salem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

