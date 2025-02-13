rule PWS_Win32_Tansteal_A_2147577544_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tansteal.gen!A"
        threat_id = "2147577544"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tansteal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Password Not Saved or Blank !" wide //weight: 2
        $x_2_2 = "http://www.irchatan.com/needfile/ctfmon.exe" wide //weight: 2
        $x_2_3 = "fatehazizi 56656" wide //weight: 2
        $x_2_4 = "IRCHATAN" wide //weight: 2
        $x_2_5 = "This User Hacked BY iRcHaTaN PaSsWoRD Sender v 7.1 ===>" wide //weight: 2
        $x_2_6 = "http://www.irchatan.com/needfile/ctfmon.dll" wide //weight: 2
        $x_2_7 = "Magic-Dialup-Password v1.2 Coded by : Magic_h2001 - magic_h2001@yahoo.com" wide //weight: 2
        $x_2_8 = "Hacked By iRcHaTaN DiaL Sender:" wide //weight: 2
        $x_2_9 = "Copyright (c) 2004 - www.zahackers.20m.com - Iran-Zahedan - 20/05/2004" wide //weight: 2
        $x_2_10 = "http://www.irchatan.com/needfile/msinet.dll" wide //weight: 2
        $x_2_11 = "<Form name=mail method=\"post\" action=\"http://www.irchatan.com/isofts/email.php" wide //weight: 2
        $x_2_12 = "YahooBuddyMain" wide //weight: 2
        $x_2_13 = "YDisconnectedWindow" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

