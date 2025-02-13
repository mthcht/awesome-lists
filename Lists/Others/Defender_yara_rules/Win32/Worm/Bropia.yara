rule Worm_Win32_Bropia_A_2147583052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bropia.gen!A"
        threat_id = "2147583052"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bropia"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\\Messenger\\msmsgs.exe\\3" ascii //weight: 5
        $x_5_2 = "MSN_OnIMWindowCreated" ascii //weight: 5
        $x_5_3 = "EVENT_SINK_Invoke" ascii //weight: 5
        $x_5_4 = "{ENTER}" wide //weight: 5
        $x_5_5 = "{ESC}" wide //weight: 5
        $x_4_6 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 49 00 43 00 52 00 4f 00 53 00 4f 00 46 00 54 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 56 00 45 00 52 00 53 00 49 00 4f 00 4e 00 5c 00 52 00 55 00 4e 00 00 00 0c 00 00 00 53 00 6b 00 6d 00 78 00 64 00 62 00 00 00 00 00 3c 00 00 00 43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00}  //weight: 4, accuracy: High
        $x_3_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 66 00 6c 00 61 00 67 00 72 00 61 00 73 00 62 00 62 00 62 00 37 00 2e 00 [0-64] 2f 00 42 00 42 00 42 00 37 00 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Bropia_B_2147583255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bropia.gen!B"
        threat_id = "2147583255"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bropia"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\Messenger\\msmsgs.exe\\3" ascii //weight: 5
        $x_5_2 = "MSN_OnIMWindowCreated" ascii //weight: 5
        $x_5_3 = "EVENT_SINK_Invoke" ascii //weight: 5
        $x_5_4 = "\\MrX-world.dat" wide //weight: 5
        $x_5_5 = "Wscript.shell" wide //weight: 5
        $x_1_6 = "Hack Gemaakt Door Mr.X" wide //weight: 1
        $x_1_7 = "Msn: mr_x_m5n@hotmail.com" wide //weight: 1
        $x_1_8 = "Site: WwW.Mrx-World.Net" wide //weight: 1
        $x_1_9 = "TryMsnMsgrShutdown" wide //weight: 1
        $x_1_10 = "Mr.X - Msn Soldier" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Bropia_C_2147583256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bropia.gen!C"
        threat_id = "2147583256"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bropia"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Messenger\\msmsgs.exe\\3" ascii //weight: 10
        $x_5_2 = "EVENT_SINK_Invoke" ascii //weight: 5
        $x_5_3 = "{Enter}" wide //weight: 5
        $x_5_4 = "Msn will shut down for maintenance in 1 minute You will automatically be signed out at that time" ascii //weight: 5
        $x_5_5 = "click Help Topics for instructions on resetting your password. 0x81000303" wide //weight: 5
        $x_5_6 = "\\bootstat.dat" wide //weight: 5
        $x_1_7 = "Sorry, we could not sign you in because the sign-in name you entered does not exist" wide //weight: 1
        $x_1_8 = "xx_bww@hotmail.com" wide //weight: 1
        $x_1_9 = "explorer http://memberservices.passport.net/memberservice.srf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Bropia_D_2147583257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bropia.gen!D"
        threat_id = "2147583257"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bropia"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Messenger\\msmsgs.exe\\3" ascii //weight: 10
        $x_5_2 = "EVENT_SINK_Invoke" ascii //weight: 5
        $x_5_3 = "{Enter}" wide //weight: 5
        $x_1_4 = "CALL IT f K THX :) f" wide //weight: 1
        $x_1_5 = "http://69.64.36.110/msn.php?email=" wide //weight: 1
        $x_1_6 = "http://Viewpics.DYNU.com/views.php?dir=pics&section=hot&clip=14" ascii //weight: 1
        $x_1_7 = "wanna see me in summer pool at our house http://strategosvideo4.com/1547.avi.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

