rule HackTool_Win32_Yahooboot_A_2147605800_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Yahooboot.A"
        threat_id = "2147605800"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Yahooboot"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*\\AC:\\Documents and Settings\\Administrator\\Desktop\\God of boot warr\\snoopbooter.vbp" wide //weight: 1
        $x_1_2 = "http://opi.yahoo.com/online?u=" wide //weight: 1
        $x_1_3 = "<mingle><vitality expire-mins=\"480\" t=\"1197984157\" c=\"100\">" wide //weight: 1
        $x_1_4 = "Load bots List" wide //weight: 1
        $x_1_5 = "Boot Warr Goodbye2" wide //weight: 1
        $x_1_6 = "Status: Load Bots List" wide //weight: 1
        $x_1_7 = "xpcontrols.ocx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Yahooboot_B_2147605828_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Yahooboot.B"
        threat_id = "2147605828"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Yahooboot"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YMSG12_ScriptedMind_Encrypt" ascii //weight: 1
        $x_1_2 = "YMSG.dll" ascii //weight: 1
        $x_1_3 = "No Bots Loaded!" ascii //weight: 1
        $x_1_4 = "Attack Complete!" ascii //weight: 1
        $x_1_5 = "E9Booter" ascii //weight: 1
        $x_1_6 = "\\Software\\APirate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Yahooboot_C_2147647581_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Yahooboot.C"
        threat_id = "2147647581"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Yahooboot"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Yahoo Room Booter" wide //weight: 3
        $x_3_2 = "You must load your bots and login !!!" wide //weight: 3
        $x_2_3 = "ModRoomPcks" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Yahooboot_D_2147650207_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Yahooboot.D"
        threat_id = "2147650207"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Yahooboot"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "You try to boot the creator of this booter !!! bye !!!" wide //weight: 4
        $x_2_2 = "psycho_logic666" wide //weight: 2
        $x_2_3 = "Status:Bot Not Loged In" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

