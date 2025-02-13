rule Worm_Win32_Semail_A_2147574158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Semail.A"
        threat_id = "2147574158"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Semail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "USERCMD" ascii //weight: 1
        $x_1_2 = "<PID>" ascii //weight: 1
        $x_1_3 = "<ID>" ascii //weight: 1
        $x_1_4 = "<UIN>" ascii //weight: 1
        $x_2_5 = "<LASTCMD>" ascii //weight: 2
        $x_3_6 = "get_command.php?PID=<PID>&ID=<ID>&LASTCMD=<LASTCMD>" ascii //weight: 3
        $x_1_7 = "ATTACHMENT" ascii //weight: 1
        $x_1_8 = "\\Internet Explorer\\Extensions\\{" ascii //weight: 1
        $x_1_9 = "if exist %1 del %1 > nul" ascii //weight: 1
        $x_1_10 = "del %0 > nul" ascii //weight: 1
        $x_1_11 = "RasGetCountryInfoA" ascii //weight: 1
        $x_1_12 = {2d 75 69 6e 20 00}  //weight: 1, accuracy: High
        $x_2_13 = {60 e8 00 00 00 00 5d eb 26}  //weight: 2, accuracy: High
        $x_1_14 = "FreeOfCharge" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Semail_2147582339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Semail"
        threat_id = "2147582339"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Semail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Kazaa" ascii //weight: 1
        $x_2_2 = "ol.Application.GetNamespace('MAPI')" ascii //weight: 2
        $x_2_3 = "Software\\Microsoft\\WAB\\DLLPath" ascii //weight: 2
        $x_1_4 = "cmd /C cscript" ascii //weight: 1
        $x_2_5 = "%s, %d %s %d %02d:%02d:%02d" ascii //weight: 2
        $x_1_6 = "=?iso-8859-1?Q?" ascii //weight: 1
        $x_1_7 = "MAIL FROM:<%s>" ascii //weight: 1
        $x_1_8 = "RCPT TO:<%s>" ascii //weight: 1
        $x_2_9 = "nobody@nowhere.com" ascii //weight: 2
        $x_2_10 = {81 3e 1e 00 01 30 75 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

