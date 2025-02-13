rule Backdoor_Win32_Hilterat_Server_2147592551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hilterat.gen!Server"
        threat_id = "2147592551"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hilterat"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {eb 65 45 78 65 53 74 65 61 6c 74 68 20 56 32 20}  //weight: 5, accuracy: High
        $x_5_2 = {60 e8 00 00 00 00 5d 81 ed 40 28 40 00 b9 16 00}  //weight: 5, accuracy: High
        $x_1_3 = "@*\\AC:\\Dan\\sources\\RAT Server\\Project1.vbp" wide //weight: 1
        $x_1_4 = "2c49f800-c2dd-11cf-9ad6-0080c7e7b78d" wide //weight: 1
        $x_1_5 = "28C4C820-401A-101B-A3C9-08002B2F49FB" wide //weight: 1
        $x_1_6 = "c:\\WINDOWS\\system32\\hrt.exe" wide //weight: 1
        $x_1_7 = "Alert!" wide //weight: 1
        $x_1_8 = "Someone is talking to you!" wide //weight: 1
        $x_1_9 = "Message to send back." wide //weight: 1
        $x_1_10 = "chat+" wide //weight: 1
        $x_1_11 = "rundll32 mouse,disable" wide //weight: 1
        $x_1_12 = "rundll32 keyboard,disable" wide //weight: 1
        $x_1_13 = "set Cdaudio door open" wide //weight: 1
        $x_1_14 = "set Cdaudio door closed" wide //weight: 1
        $x_1_15 = "Your computer says:" wide //weight: 1
        $x_1_16 = "Stolen" wide //weight: 1
        $x_1_17 = "Report" wide //weight: 1
        $x_1_18 = "Server : " wide //weight: 1
        $x_1_19 = "<GH>|" wide //weight: 1
        $x_1_20 = "<EF>|" wide //weight: 1
        $x_1_21 = "Downloaded " wide //weight: 1
        $x_1_22 = "Successfully" wide //weight: 1
        $x_1_23 = "Report|" wide //weight: 1
        $x_1_24 = "Uploaded Successfully" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hilterat_Client_2147592552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hilterat.gen!Client"
        threat_id = "2147592552"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hilterat"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {eb 65 45 78 65 53 74 65 61 6c 74 68 20 56 32 20}  //weight: 5, accuracy: High
        $x_5_2 = {60 e8 00 00 00 00 5d 81 ed 40 28 40 00 b9 16 00}  //weight: 5, accuracy: High
        $x_1_3 = "cmdSendKeyboard" wide //weight: 1
        $x_1_4 = "cmdEnter" wide //weight: 1
        $x_1_5 = "\\Account.txt" wide //weight: 1
        $x_1_6 = "Username+Password" wide //weight: 1
        $x_1_7 = "Shittylogin" wide //weight: 1
        $x_1_8 = "Connected" wide //weight: 1
        $x_1_9 = "\\CMD Log.txt" wide //weight: 1
        $x_1_10 = "\\Key Log.txt" wide //weight: 1
        $x_1_11 = "Victims mouse disabled. Enabled upon restart." wide //weight: 1
        $x_1_12 = "Victims keyboard disabled. Enabled upon restart." wide //weight: 1
        $x_1_13 = "Victims CD tray is now closed." wide //weight: 1
        $x_1_14 = "Task Manager has now been disabled." wide //weight: 1
        $x_1_15 = "Victims computer now has a black screen." wide //weight: 1
        $x_1_16 = "Victims computer has just beeped." wide //weight: 1
        $x_1_17 = "Victims mouse buttons are now swapped." wide //weight: 1
        $x_1_18 = "Victims computer has now said hi to them via msgbox." wide //weight: 1
        $x_1_19 = "Report|" wide //weight: 1
        $x_1_20 = "Victims mouse buttons are now unswapped." wide //weight: 1
        $x_1_21 = "Server : " wide //weight: 1
        $x_1_22 = "/Stolen Files/" wide //weight: 1
        $x_1_23 = "<GH>|" wide //weight: 1
        $x_1_24 = "<EF>|" wide //weight: 1
        $x_1_25 = "HitleRAT v1.0 Client" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

