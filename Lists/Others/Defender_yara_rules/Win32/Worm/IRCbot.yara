rule Worm_Win32_IRCbot_C_2147637880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/IRCbot.C"
        threat_id = "2147637880"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 00 65 00 73 00 74 00 72 00 30 00 62 00 30 00 3e 00 50 00 49 00 4e 00 47 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {2a 00 2a 00 2a 00 4b 00 6c 00 6f 00 67 00 67 00 33 00 72 00 20 00 3a 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 00 69 00 6e 00 55 00 70 00 64 00 61 00 74 00 65 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_IRCbot_F_2147641938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/IRCbot.F"
        threat_id = "2147641938"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = " :E-Mule Spread Complete" wide //weight: 4
        $x_3_2 = "12Fetching Keys..." wide //weight: 3
        $x_4_3 = " :[DDOS] Attack Started " wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_IRCbot_I_2147649448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/IRCbot.I"
        threat_id = "2147649448"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "The One botspread.start" ascii //weight: 1
        $x_1_2 = "[P2P Spread]:" ascii //weight: 1
        $x_1_3 = "[Email Spread]:" ascii //weight: 1
        $x_1_4 = "[LAN Spread]:" ascii //weight: 1
        $x_1_5 = "[HTML Infector]:" ascii //weight: 1
        $x_1_6 = "[MSN Spreader]: Sent to %i Contacts." ascii //weight: 1
        $x_1_7 = "Infected Drive %s" ascii //weight: 1
        $x_1_8 = "[SSYN]: Flooding %s:%s for %s seconds." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_IRCbot_K_2147651765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/IRCbot.K"
        threat_id = "2147651765"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "%ss.lnk" ascii //weight: 1
        $x_1_3 = "PRIVMSG" ascii //weight: 1
        $x_1_4 = "JOIN" ascii //weight: 1
        $x_1_5 = "NICK" ascii //weight: 1
        $x_1_6 = {83 f8 02 75 2c 8b 55 fc 0f be 02 83 c8 20 83 f8 61 74 1e 8b 4d fc 0f be 11 83 ca 20 83 fa 62 74 10 8b 45 08 50 8b 4d fc 51}  //weight: 1, accuracy: High
        $x_1_7 = {83 fa 6a 7d 25 6a 0c 6a 32 0f b6 85 37 fe ff ff 6b c0 64 05 ?? ?? ?? ?? 50 8d 8d 38 fe ff ff 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Worm_Win32_IRCbot_M_2147653500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/IRCbot.M"
        threat_id = "2147653500"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\{%s-%s}\\UDP_Module.dll" ascii //weight: 1
        $x_1_2 = "%s\\Microsoft_Removal_Tool.bat" ascii //weight: 1
        $x_1_3 = {55 44 50 5f 46 6c 6f 6f 64 00 55 44 50 5f 46 6c 6f 6f 64 5f 50 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 49 43 4b ?? ?? ?? ?? 4a 4f 49 4e}  //weight: 1, accuracy: Low
        $x_1_5 = {50 49 4e 47 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 52 49 56 4d 53 47}  //weight: 1, accuracy: Low
        $x_1_6 = "0New Infection via USB Spread" ascii //weight: 1
        $x_1_7 = {0f 55 44 50 20 4d 6f 64 75 6c 65 20 54 65 72 6d 69 6e 61 74 65 64}  //weight: 1, accuracy: High
        $x_1_8 = "<<.|.4WGet Error.|..4>>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Worm_Win32_IRCbot_O_2147684419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/IRCbot.O"
        threat_id = "2147684419"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 5f 41 75 74 6f 52 75 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "VNC%d.%d %s: %s:%d - [AuthBypass]" ascii //weight: 1
        $x_1_3 = "Look at this picture %s" ascii //weight: 1
        $x_1_4 = "cmd /c net stop SharedAccess &echo open %s %d >> ij &echo user %s %s >> ij &echo" ascii //weight: 1
        $x_1_5 = {00 63 66 74 70 2e 67 65 74 00}  //weight: 1, accuracy: High
        $x_1_6 = "Scanner already running" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

