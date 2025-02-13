rule TrojanDropper_Win32_Alureon_J_127339_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Alureon.J"
        threat_id = "127339"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a d1 80 c2 ?? 30 14 (01|19|31|39) 83 c1 01 3b (c8|cb|ce|cf) 72 f1 c3}  //weight: 10, accuracy: Low
        $x_1_2 = "tdssData" ascii //weight: 1
        $x_1_3 = "tdssadw.dll" ascii //weight: 1
        $x_1_4 = "\\tdssinit.dll" ascii //weight: 1
        $x_1_5 = "tdsshelper.dll" wide //weight: 1
        $x_1_6 = "\\device\\namedpipe\\tdlcmd" wide //weight: 1
        $x_1_7 = {61 64 77 5f 64 6c 6c [0-1] 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Alureon_T_149300_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Alureon.T"
        threat_id = "149300"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b 21 40 49 6e 73 74 61 6c 6c 40 21 55 54 46 2d 38 21 0d 0a 54 69 74 6c 65 3d 22 43 72 61 63 6b 20 61 6e 64 20 53 65 72 69 61 6c 22 0d 0a 42 65 67 69 6e 50 72 6f 6d 70 74 3d 22 44 69 73 61 62 6c 65 20 61 6e 74 69 76 69 72 75 73 65 73 20 62 65 66 6f 72 65 20 70 61 74 63 68 69 6e 67 21 5c 6e 43 6f 6e 74 69 6e 75 65 3f 22 0d 0a 52 75 6e 50 72 6f 67 72 61 6d 3d 22 73 65 74 75 70 2e 62 61 74 22 0d 0a 3b 21 40 49 6e 73 74 61 6c 6c 45 6e 64 40 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Alureon_V_152591_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Alureon.V"
        threat_id = "152591"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 78 65 63 44 6f 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = "7za.exe x" ascii //weight: 1
        $x_1_3 = "a1.7z -aoa -o" ascii //weight: 1
        $x_1_4 = {2d 70 6c 6f 6c 6d 69 6c 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Alureon_Z_165036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Alureon.Z"
        threat_id = "165036"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\ExecDos.dll" ascii //weight: 1
        $x_1_2 = "\\7za.exe\" x \"" ascii //weight: 1
        $x_1_3 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_4 = "Set wsc = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_5 = "Set batch = fso.CreateTextFile(" ascii //weight: 1
        $x_1_6 = "batch.WriteLine \"cmd /C  ping -n 1  localhost > nul & del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDropper_Win32_Alureon_E_195706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Alureon.gen!E"
        threat_id = "195706"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a5 22 02 0a dd dd 9d d9 a5 22 02 12 dd dd 9d d9 6a 22 02 f6 2d dd 53 fa dd 53 f6 dc 53 f2 dc 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

