rule Backdoor_Win32_Rukap_A_2147575037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rukap.gen!A"
        threat_id = "2147575037"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rukap"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {6a 01 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? ff d6 85 c0 74 55 53 8b 1d ?? ?? ?? ?? 55 8b 2d ?? ?? ?? ?? 57 8b 3d ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d7 68 ?? ?? ?? ?? ff d3 a1}  //weight: 100, accuracy: Low
        $x_100_2 = {3d b7 00 00 00 75 0e 56 ff 15 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 33 c0 5e}  //weight: 100, accuracy: Low
        $x_1_3 = "CreateMutexA" ascii //weight: 1
        $x_1_4 = "GetLastError" ascii //weight: 1
        $x_1_5 = "CloseHandle" ascii //weight: 1
        $x_100_6 = {52 6a 04 50 56 e8 ?? ?? ?? ?? 85 c0 74 3b 8b 54 24 1c 8d 4c 24 20 68 04 01 00 00 51 52 56 e8 ?? ?? ?? ?? 8b 84 24 28 11 00 00 8d 4c 24 20 50 51 e8 ?? ?? ?? ?? 83 c4 08 85 c0 75 0d 50 56}  //weight: 100, accuracy: Low
        $x_1_7 = "EnumProcessModules" ascii //weight: 1
        $x_1_8 = "GetModuleBaseNameA" ascii //weight: 1
        $x_1_9 = "TerminateProcess" ascii //weight: 1
        $x_1_10 = "ChangeServiceConfigA" ascii //weight: 1
        $x_1_11 = "InternetWriteFile" ascii //weight: 1
        $x_1_12 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_13 = "CreateServiceA" ascii //weight: 1
        $x_1_14 = "RegCreateKeyExA" ascii //weight: 1
        $x_1_15 = "RegDeleteValueA" ascii //weight: 1
        $x_1_16 = "RasEnumConnectionsA" ascii //weight: 1
        $x_1_17 = "RegisterServiceProcess" ascii //weight: 1
        $x_1_18 = "WS2_32.DLL" ascii //weight: 1
        $x_12_19 = {da 40 83 f8 20 88 1c 31 75 02 33 c0 41 3b cf 72 e5}  //weight: 12, accuracy: High
        $x_2_20 = "Software\\Microsoft\\Direct" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Rukap_B_2147602786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rukap.gen!B"
        threat_id = "2147602786"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rukap"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hello 2 AV programmers from India. You debug 'MoonClicker' :)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

