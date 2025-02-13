rule PWS_Win32_Perfwo_A_2147583596_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Perfwo.A"
        threat_id = "2147583596"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Perfwo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ElementClient" ascii //weight: 3
        $x_1_2 = "elementclient.exe" ascii //weight: 1
        $x_3_3 = "/sendmail." ascii //weight: 3
        $x_2_4 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 2
        $x_1_5 = "User=" ascii //weight: 1
        $x_1_6 = "Pass=" ascii //weight: 1
        $x_2_7 = "WriteProcessMemory" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Perfwo_C_2147584524_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Perfwo.C"
        threat_id = "2147584524"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Perfwo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "elementclient.exe" ascii //weight: 1
        $x_1_2 = "drivers\\etc\\hosts" ascii //weight: 1
        $x_1_3 = "serverlist.ini" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "Borland" ascii //weight: 1
        $x_1_6 = "User-Agent: Mozilla" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Perfwo_D_2147584630_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Perfwo.D"
        threat_id = "2147584630"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Perfwo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_2 = "elementclient" ascii //weight: 1
        $x_1_3 = "sendmail.asp#" ascii //weight: 1
        $x_1_4 = "Pass=" ascii //weight: 1
        $x_1_5 = "GetForegroundWindow" ascii //weight: 1
        $x_1_6 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_7 = "Content-Type: application" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Perfwo_B_2147595040_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Perfwo.B"
        threat_id = "2147595040"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Perfwo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 ff 32 64 89 22 33 c0 89 45 e8 8d 45 e8 50 8b 45 f4}  //weight: 1, accuracy: High
        $x_1_2 = {b0 01 5b c3 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 43 72 65 61 74 65 54 6f 6f 6c}  //weight: 1, accuracy: High
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "CreateRemoteThread" ascii //weight: 1
        $x_1_5 = "drivers\\etc\\hosts" ascii //weight: 1
        $x_1_6 = "CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_7 = "$$tmp.bat" ascii //weight: 1
        $x_1_8 = "client.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Perfwo_E_2147597163_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Perfwo.E"
        threat_id = "2147597163"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Perfwo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 63 63 65 70 74 3a 20 2a 2f 2a 00 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: High
        $x_1_2 = {2e 64 6c 6c 00 48 6f 6f 6b 6f 66 66 00 48 6f 6f 6b 6f 6e}  //weight: 1, accuracy: High
        $x_1_3 = "elementclient" ascii //weight: 1
        $x_1_4 = "DoPacth.VirtualProtect" ascii //weight: 1
        $x_1_5 = "GamePatch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Perfwo_L_2147598742_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Perfwo.L"
        threat_id = "2147598742"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Perfwo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff ff ff ff 0e 00 00 00 61 75 74 6f 75 70 64 61 74 65 2e 65 78 65 00 00 ff ff ff ff 0c 00 00 00 61 76 63 6f 6e 73 6f 6c 2e 65 78 65 00 00 00 00 ff ff ff ff 09 00 00 00 61 76 65 33 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "CreateRemoteThread" ascii //weight: 1
        $x_1_4 = "drivers\\etc\\hosts" ascii //weight: 1
        $x_1_5 = "**__L2spy__**" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Perfwo_M_2147598743_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Perfwo.M"
        threat_id = "2147598743"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Perfwo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WriteProcessMemory" ascii //weight: 1
        $x_1_2 = "CreateRemoteThread" ascii //weight: 1
        $x_1_3 = "drivers\\etc\\hosts" ascii //weight: 1
        $x_1_4 = "$$tmp.bat" ascii //weight: 1
        $x_1_5 = "Explorer.exe crs.exe" ascii //weight: 1
        $x_1_6 = {ff ff ff ff 0b 00 00 00 49 50 41 52 4d 4f 52 2e 45 58 45 00 ff ff ff ff 0b 00 00 00 52 41 56 54 41 53 4b 2e 45 58 45 00 ff ff ff ff 07 00 00 00 52 41 56 2e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_7 = "ELEMENTCLIENT.EXE" ascii //weight: 1
        $x_1_8 = {ff ff ff ff 0c 00 00 00 45 58 50 4c 4f 52 45 52 2e 45 58 45 00 00 00 00 ff ff ff ff 0d 00 00 00 77 69 6e 73 6f 63 6b 30 31 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

