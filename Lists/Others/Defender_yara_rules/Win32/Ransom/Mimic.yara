rule Ransom_Win32_Mimic_MA_2147847147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mimic.MA!MTB"
        threat_id = "2147847147"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SelfDelete" ascii //weight: 1
        $x_1_2 = "hidcon" ascii //weight: 1
        $x_2_3 = "Everything64.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mimic_MA_2147847147_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mimic.MA!MTB"
        threat_id = "2147847147"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c0 c7 45 e8 00 00 00 00 68 ?? ?? 5d 00 8d 4d d8 c7 45 ec 07 00 00 00 66 89 45 d8 e8 ?? ?? fd ff 8b 45 e8 8d 55 8c 83 7d bc 08 8d 4d a8 6a 00 0f 43 4d a8 52 6a 00 68 06 01 02 00 8d 1c 00 33 c0 38 05 ?? ?? 5e}  //weight: 5, accuracy: Low
        $x_2_2 = "MIMIC_LOG.txt" wide //weight: 2
        $x_2_3 = "DontDecompileMePlease" ascii //weight: 2
        $x_2_4 = "Delete Shadow Copies" wide //weight: 2
        $x_2_5 = "SELECT * FROM Win32_ShadowCopy" wide //weight: 2
        $x_2_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_1_7 = "ChaCha20 for x86, CRYPTOGAMS by" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mimic_DA_2147905035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mimic.DA!MTB"
        threat_id = "2147905035"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mimic 4.3" wide //weight: 1
        $x_1_2 = "Delete Shadow Copies" wide //weight: 1
        $x_1_3 = "\\temp\\lock.txt" wide //weight: 1
        $x_1_4 = "powershell.exe -ExecutionPolicy Bypass \"Get-VM | Stop-VM" wide //weight: 1
        $x_1_5 = "Software\\Classes\\mimicfile\\shell\\open\\command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mimic_ATZ_2147920882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mimic.ATZ!MTB"
        threat_id = "2147920882"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 65 f8 00 0f af 05 d8 6e 5f 00 8d 4d f0 33 d2 c7 45 fc e8 9a 53 00 f7 f7 03 05 d8 6e 5f 00 50}  //weight: 1, accuracy: High
        $x_1_2 = {8b 56 08 8b 45 08 c1 ea 03 c1 e8 03 2b d0}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 40 f0 0f c1 41 14 40 83 f8 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mimic_YAB_2147920969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mimic.YAB!MTB"
        threat_id = "2147920969"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-ExecutionPolicy Bypass \"Get-VM | Stop-VM" wide //weight: 1
        $x_1_2 = "Everything.exe" wide //weight: 1
        $x_5_3 = "Del /f /q /a *.exe *.ini *.dll *.bat *.db" wide //weight: 5
        $x_5_4 = "bcdedit.exe /set {default} recoveryenabled no" wide //weight: 5
        $x_1_5 = "xdel.exe\" -accepteula -p 1 -c" wide //weight: 1
        $x_1_6 = "-dir" wide //weight: 1
        $x_1_7 = "-prot" wide //weight: 1
        $x_1_8 = "-tail" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mimic_YAA_2147920971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mimic.YAA!MTB"
        threat_id = "2147920971"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RunProgram=\"hidcon:7za.exe i" ascii //weight: 1
        $x_10_2 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 37 7a 61 2e 65 78 65 20 78 20 2d 79 20 2d 70 [0-20] 20 45 76 65 72 79 74 68 69 6e 67 36 34 2e 64 6c 6c}  //weight: 10, accuracy: Low
        $x_1_3 = "RunProgram=\"hidcon:\\\"datastore@cyberfear.com_no gui.exe\\\" %SfxVarCmdLine0%" ascii //weight: 1
        $x_1_4 = "GUIFlags=\"2+512+8192" ascii //weight: 1
        $x_1_5 = "MiscFlags=\"1+2+16" ascii //weight: 1
        $x_1_6 = "GUIMode=\"2" ascii //weight: 1
        $x_1_7 = "SelfDelete=\"1" ascii //weight: 1
        $x_1_8 = ";!@InstallEnd@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

