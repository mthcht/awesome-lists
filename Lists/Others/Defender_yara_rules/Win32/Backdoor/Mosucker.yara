rule Backdoor_Win32_Mosucker_AB_2147584358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mosucker.AB"
        threat_id = "2147584358"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mosucker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "145"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "MoSucker" wide //weight: 50
        $x_50_2 = "Thanx for using MoSucker. Have a nice day." wide //weight: 50
        $x_50_3 = "MoSucker-server is online! Victim=%VN, IP=%IP, Port=%PT, Password=%PW. This message goes to: %AU" wide //weight: 50
        $x_10_4 = "winstart.bat" wide //weight: 10
        $x_10_5 = "wininit.ini" wide //weight: 10
        $x_10_6 = "del %windir%\\temp.bat" wide //weight: 10
        $x_10_7 = "a@bc.de" wide //weight: 10
        $x_10_8 = "AdminCanKick" wide //weight: 10
        $x_5_9 = "Victim name" wide //weight: 5
        $x_5_10 = "Victim's Computer will crash soon!" wide //weight: 5
        $x_5_11 = "Only the admin can close the server." wide //weight: 5
        $x_5_12 = "C:\\con\\con" wide //weight: 5
        $x_5_13 = "C:\\nul\\nul" wide //weight: 5
        $x_5_14 = "Systemtray hidden" wide //weight: 5
        $x_5_15 = "Systemtray shown" wide //weight: 5
        $x_5_16 = "Mouse disabled" wide //weight: 5
        $x_5_17 = "RESTARTME" wide //weight: 5
        $x_5_18 = "ADMINLOGIN:" wide //weight: 5
        $x_1_19 = "You are not an admin!" wide //weight: 1
        $x_1_20 = "You are not allowed to kick users." wide //weight: 1
        $x_1_21 = "AutoRestoreServer" wide //weight: 1
        $x_1_22 = "PermanentConnection" wide //weight: 1
        $x_1_23 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_24 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" wide //weight: 1
        $x_1_25 = "HKEY_USERS\\.DEFAULT\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_26 = "ren %windir%\\~bckup.tmp ~bckup.exe" wide //weight: 1
        $x_1_27 = "%windir%\\~bckup.exe -update" wide //weight: 1
        $x_1_28 = "del %windir%\\~bckup.exe" wide //weight: 1
        $x_1_29 = "if exist %windir%\\~bckup.exe goto TryAgain2" wide //weight: 1
        $x_1_30 = "c:\\~bckup4.tmp" wide //weight: 1
        $x_1_31 = "ftp.simloads.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 4 of ($x_10_*) and 9 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_50_*) and 4 of ($x_10_*) and 10 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_50_*) and 5 of ($x_10_*) and 7 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_50_*) and 5 of ($x_10_*) and 8 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_50_*) and 5 of ($x_10_*) and 9 of ($x_5_*))) or
            ((2 of ($x_50_*) and 7 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_50_*) and 8 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_50_*) and 9 of ($x_5_*))) or
            ((2 of ($x_50_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_50_*) and 1 of ($x_10_*) and 6 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_50_*) and 1 of ($x_10_*) and 7 of ($x_5_*))) or
            ((2 of ($x_50_*) and 2 of ($x_10_*) and 3 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_50_*) and 2 of ($x_10_*) and 4 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_50_*) and 2 of ($x_10_*) and 5 of ($x_5_*))) or
            ((2 of ($x_50_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_50_*) and 3 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_50_*) and 3 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_50_*) and 4 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_50_*) and 4 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_50_*) and 5 of ($x_10_*))) or
            ((3 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Mosucker_2147594944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mosucker"
        threat_id = "2147594944"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mosucker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "290"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "shutdown -t 0" wide //weight: 30
        $x_30_2 = "ActiveXExe" wide //weight: 30
        $x_10_3 = "HttpSendRequestA" ascii //weight: 10
        $x_10_4 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_5 = "Process32First" ascii //weight: 10
        $x_10_6 = "Process32Next" ascii //weight: 10
        $x_10_7 = "socket" ascii //weight: 10
        $x_10_8 = "getsockname" ascii //weight: 10
        $x_10_9 = "select" ascii //weight: 10
        $x_10_10 = "recv" ascii //weight: 10
        $x_10_11 = "shutdown" ascii //weight: 10
        $x_10_12 = "listen" ascii //weight: 10
        $x_10_13 = "{1D5BE4B5-FA4A-452D-9CDD-5DB35105E7EB}" wide //weight: 10
        $x_5_14 = "Stealth" ascii //weight: 5
        $x_5_15 = "FunOptions" ascii //weight: 5
        $x_5_16 = "MO_NOTE" wide //weight: 5
        $x_5_17 = "MO_BMPJPG" wide //weight: 5
        $x_5_18 = "MO_MEEP" wide //weight: 5
        $x_5_19 = "MO_QNAVD" wide //weight: 5
        $x_5_20 = "MO_PLGNS" wide //weight: 5
        $x_5_21 = "was executed" wide //weight: 5
        $x_5_22 = "1SB:Thread Suspended" wide //weight: 5
        $x_5_23 = "1SB:Thread Resumed" wide //weight: 5
        $x_5_24 = "1SB:Services Terminated" wide //weight: 5
        $x_5_25 = "[MO]" wide //weight: 5
        $x_10_26 = "Connected to Webcam" wide //weight: 10
        $x_10_27 = "http://web.icq.com/friendship/email_thank_you?failed_url=%2Ffriendship%2Fsend_by_email&folder_id=" wide //weight: 10
        $x_10_28 = "&Extra_Params_Counte=0&nick_name=" wide //weight: 10
        $x_10_29 = "&user_email=" wide //weight: 10
        $x_10_30 = "&user_uin=1999&friend_nickname=" wide //weight: 10
        $x_10_31 = "&friend_contact=" wide //weight: 10
        $x_10_32 = "cam.jpg" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_30_*) and 17 of ($x_10_*) and 12 of ($x_5_*))) or
            ((2 of ($x_30_*) and 18 of ($x_10_*) and 10 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Mosucker_Y_2147605394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mosucker.Y"
        threat_id = "2147605394"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mosucker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MMP07.CommandLine1" ascii //weight: 10
        $x_10_2 = {69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 00 45 78 70 6c 6f 72 65 72 00 00 4d 4d 50 30 37 00}  //weight: 10, accuracy: High
        $x_4_3 = "\\Guido\\Desktop\\" wide //weight: 4
        $x_1_4 = "Drive1" ascii //weight: 1
        $x_1_5 = "Restart" ascii //weight: 1
        $x_1_6 = "tmrOnline" ascii //weight: 1
        $x_1_7 = "tmrUpdater" ascii //weight: 1
        $x_1_8 = "tmrCGI" ascii //weight: 1
        $x_1_9 = "tmrICQ" ascii //weight: 1
        $x_1_10 = "lblICQ" ascii //weight: 1
        $x_1_11 = "tmrConnect" ascii //weight: 1
        $x_1_12 = "tmrPassword" ascii //weight: 1
        $x_1_13 = "lstDataTrans" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Mosucker_AA_2147624076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mosucker.AA"
        threat_id = "2147624076"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mosucker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2c49f800-c2dd-11cf-9ad6-0080c7e7b78d" wide //weight: 1
        $x_1_2 = "Server.vbp" wide //weight: 1
        $x_1_3 = "\\update.bat" wide //weight: 1
        $x_1_4 = {47 00 65 00 74 00 44 00 61 00 74 00 61 00 00 00 02 00 00 00 2e 00 00 00 52 00 65 00 6d 00 6f 00 74 00 65 00 48 00 6f 00 73 00 74 00 00 00 00 00 52 00 65 00 6d 00 6f 00 74 00 65 00 50 00 6f 00 72 00 74 00 00 00 00 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

