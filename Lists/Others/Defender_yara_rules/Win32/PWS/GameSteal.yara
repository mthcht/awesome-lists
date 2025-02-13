rule PWS_Win32_GameSteal_A_2147583576_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/GameSteal.A"
        threat_id = "2147583576"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "GameSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E-China" ascii //weight: 1
        $x_1_2 = "WowExec" ascii //weight: 1
        $x_1_3 = {57 6f 57 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "YB_OnlineClient" ascii //weight: 1
        $x_1_5 = "#32770" ascii //weight: 1
        $x_1_6 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_GameSteal_B_2147583580_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/GameSteal.B"
        threat_id = "2147583580"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "GameSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_2 = "%s\\..\\WTF\\Config.wtf" ascii //weight: 1
        $x_1_3 = "Microsoft Internet Explorer" ascii //weight: 1
        $x_1_4 = "Shanda\\Legend of Mir" ascii //weight: 1
        $x_1_5 = "Entertainment\\World of Warcraft" ascii //weight: 1
        $x_1_6 = {00 6d 69 72 2e}  //weight: 1, accuracy: High
        $x_1_7 = "Explorer\\wsock32.dll" ascii //weight: 1
        $x_1_8 = {8a c2 8a ca c0 e8 04 80 e1 0f 3c 0a 73 04 04 30 eb 02 04 37}  //weight: 1, accuracy: High
        $x_1_9 = {00 10 8d 48 05 a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule PWS_Win32_GameSteal_C_2147584629_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/GameSteal.C"
        threat_id = "2147584629"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "GameSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_2 = "ReadProcessMemory" ascii //weight: 1
        $x_1_3 = "Internet Explorer\\Main" ascii //weight: 1
        $x_1_4 = "wow.exe" ascii //weight: 1
        $x_1_5 = "woool." ascii //weight: 1
        $x_1_6 = "zhengtu" ascii //weight: 1
        $x_1_7 = "elementclient" ascii //weight: 1
        $x_1_8 = "Explorer.Exe" ascii //weight: 1
        $x_1_9 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_10 = "MsgHookOn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

