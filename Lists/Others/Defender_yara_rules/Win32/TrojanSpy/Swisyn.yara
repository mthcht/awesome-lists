rule TrojanSpy_Win32_Swisyn_A_2147629832_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Swisyn.A"
        threat_id = "2147629832"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "%APPDATA%\\Roaming\\dllhost.exe" ascii //weight: 3
        $x_3_2 = "system.bat" ascii //weight: 3
        $x_3_3 = "ntlog.sys" ascii //weight: 3
        $x_2_4 = "cmd /c REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 2
        $x_2_5 = "cmd /c REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_1_6 = "/V DLLHost /D" ascii //weight: 1
        $x_1_7 = "/V Shell /D" ascii //weight: 1
        $x_1_8 = "[AsagiOK]" ascii //weight: 1
        $x_1_9 = "[YukariOK]" ascii //weight: 1
        $x_1_10 = "[SagOK]" ascii //weight: 1
        $x_1_11 = "[Baslat]" ascii //weight: 1
        $x_1_12 = "[Backspace]" ascii //weight: 1
        $x_1_13 = "[Del]" ascii //weight: 1
        $x_1_14 = "[Tab]" ascii //weight: 1
        $x_1_15 = "[Esc]" ascii //weight: 1
        $x_1_16 = "[CapsLock]" ascii //weight: 1
        $x_1_17 = "[Clear]" ascii //weight: 1
        $x_1_18 = "[PGUP]" ascii //weight: 1
        $x_1_19 = "[Shift]" ascii //weight: 1
        $x_1_20 = "[Ctrl]" ascii //weight: 1
        $x_1_21 = "[Alt]" ascii //weight: 1
        $x_1_22 = "[Clipboard]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((16 of ($x_1_*))) or
            ((1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_3_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_3_*) and 10 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_3_*) and 7 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Swisyn_A_2147629834_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Swisyn.A"
        threat_id = "2147629834"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ntlog.sys" ascii //weight: 1
        $x_1_2 = "ntcom.dll" ascii //weight: 1
        $x_1_3 = "hazirla" ascii //weight: 1
        $x_1_4 = "user=" ascii //weight: 1
        $x_1_5 = "destino=" ascii //weight: 1
        $x_1_6 = "conteudo=" ascii //weight: 1
        $x_1_7 = "Error on FFFFFFFFF" ascii //weight: 1
        $x_1_8 = {00 2f 31 73 74 65 6d 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 6c 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_3_10 = {ff b5 c8 fe ff ff 68 ?? ?? ?? ?? ff b5 ec fe ff ff ff b5 ec fe ff ff ff b5 ec fe ff ff 68 ?? ?? ?? ?? ff b5 d0 fe ff ff ff b5 d4 fe ff ff ff b5 d0 fe ff ff ff b5 d0 fe ff ff ff b5 d8 fe ff ff 68 ?? ?? ?? ?? ff b5 cc fe ff ff ff b5 dc fe ff ff ff b5 e4 fe ff ff ff b5 e0 fe ff ff 68 ?? ?? ?? ?? ff b5 f4 fe ff ff ff b5 cc fe ff ff 68}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Swisyn_B_2147630783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Swisyn.B"
        threat_id = "2147630783"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "APPLICATION : KEYLOGGER" ascii //weight: 1
        $x_1_2 = "[Backspace]" ascii //weight: 1
        $x_1_3 = "?action=add&username=" ascii //weight: 1
        $x_1_4 = "\\PCTotalDefender\\sqlite3.dll" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "Process Monitor - Sysinternals: www.sysinternals.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Swisyn_C_2147631139_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Swisyn.C"
        threat_id = "2147631139"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Pusmint\\svchost.exe" wide //weight: 1
        $x_1_2 = "hookmibao.asp?msg=" wide //weight: 1
        $x_1_3 = "\\Pusmint\\jietu.jpg" wide //weight: 1
        $x_1_4 = "LastQQUin" wide //weight: 1
        $x_1_5 = "dnf.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Swisyn_D_2147632021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Swisyn.D"
        threat_id = "2147632021"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%.2u/%.2u/%u %.2u:%.2u" ascii //weight: 1
        $x_1_2 = "[Schowek]" ascii //weight: 1
        $x_2_3 = "C:\\InsideTm\\" ascii //weight: 2
        $x_3_4 = "D:\\program z visuala\\keylogger\\Release\\keylogger.pdb" ascii //weight: 3
        $x_1_5 = "\\log.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Swisyn_E_2147632169_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Swisyn.E"
        threat_id = "2147632169"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff}  //weight: 3, accuracy: High
        $x_3_2 = {83 c0 f8 83 f8 66 0f 87 ?? ?? 00 00 0f b6 80 ?? ?? ?? ?? ff 24 85}  //weight: 3, accuracy: Low
        $x_1_3 = "drivers.log" ascii //weight: 1
        $x_1_4 = "[Del]" ascii //weight: 1
        $x_1_5 = "[Backspace]" ascii //weight: 1
        $x_1_6 = "{Sil}" ascii //weight: 1
        $x_1_7 = "{Arrow_Up}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Swisyn_F_2147636463_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Swisyn.F"
        threat_id = "2147636463"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.31334.info/1stupload.php" ascii //weight: 1
        $x_1_2 = "\\appdata.jpg" ascii //weight: 1
        $x_1_3 = "\\win.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Swisyn_H_2147643666_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Swisyn.H"
        threat_id = "2147643666"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 83 7d fe 40 7e 63 66 83 7d fe 5a 7f 5c c7 04 24 14 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "[BrowserBack]" ascii //weight: 1
        $x_1_3 = "[NL1]" ascii //weight: 1
        $x_1_4 = "Resim cek:__" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

