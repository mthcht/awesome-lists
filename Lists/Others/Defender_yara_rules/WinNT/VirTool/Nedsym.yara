rule VirTool_WinNT_Nedsym_A_2147605134_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Nedsym.gen!A"
        threat_id = "2147605134"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Nedsym"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 06 59 8d 45 e0 50 be f6 04 01 00 8d 7d e0 f3 a5 33 f6 8d 45 f8 50 89 35 88 06 01 00}  //weight: 1, accuracy: High
        $x_1_2 = "HidePort" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Nedsym_B_2147605135_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Nedsym.gen!B"
        threat_id = "2147605135"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Nedsym"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 f6 74 85 eb 19 3b 5d 1c 75 09 c7 45 2c 06 00 00 80 eb 0b 6a 00 57 ff 75 30 e8 e2 fd ff ff 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Nedsym_C_2147605136_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Nedsym.gen!C"
        threat_id = "2147605136"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Nedsym"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 ff d3 83 c4 0c 85 c0 74 61 83 7d 08 05 75 5b ba ?? ?? 01 00 6a 10 59 33 c0 8b fa f3 ab 8b fa 6a 01 8d 46 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Nedsym_D_2147605137_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Nedsym.gen!D"
        threat_id = "2147605137"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Nedsym"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 be a0 01 00 00 00 74 25 8d 86 90 01 00 00 39 00 74 1b 6a 0c 8d 86 74 01 00 00 68 ?? ?? ?? ?? 50}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 4d 11 86 7c 6a 01 90 68 cd ab 00 00 ff d0 e9}  //weight: 1, accuracy: High
        $x_1_3 = "\\Device\\KernelExec" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_WinNT_Nedsym_E_2147614135_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Nedsym.gen!E"
        threat_id = "2147614135"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Nedsym"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Devices\\HidePort" wide //weight: 1
        $x_1_2 = {8b 3d 08 10 01 00 68 00 40 01 00 8d 45 f4 33 db 50 89 5d fc ff d7 8b 75 08 8d 45 fc 50 53 53 6a 22 8d 45 f4 50 53 56 ff 15 30 10 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Nedsym_F_2147614136_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Nedsym.gen!F"
        threat_id = "2147614136"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Nedsym"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Device\\SSDT" wide //weight: 1
        $x_1_2 = {68 1c 07 01 00 8d 4d d4 51 ff 15 9c 08 01 00 8d 55 e0 52 6a 00 68 00 01 00 00 68 20 04 00 00 8d 45 f8 50 6a 00 8b 4d 08 51 ff 15 a4 08 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Nedsym_G_2147680223_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Nedsym.gen!G"
        threat_id = "2147680223"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Nedsym"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\DosDevices\\HidePort" wide //weight: 2
        $x_1_2 = {8d 45 f4 33 db 50 89 5d fc ff d7 8b 75 08 8d 45 fc 50 53 53 6a 22 8d 45 f4 50 53 56 ff 15 ?? ?? ?? ?? 3b c3 89 45 08}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 48 08 c1 e1 02 51 ff 30 53 ff 15 2c 20 01 00 a3 ?? ?? ?? ?? 3b c3 75 07 b8 01 00 00 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

