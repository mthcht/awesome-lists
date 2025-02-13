rule Worm_Win32_Amend_A_2147600637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Amend.A"
        threat_id = "2147600637"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Amend"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OPEN=Comand.com" wide //weight: 1
        $x_1_2 = "cmd /c net share D$=d:\\" wide //weight: 1
        $x_1_3 = "1sass.exe" wide //weight: 1
        $x_1_4 = "eru_kkk@sohu.com" wide //weight: 1
        $x_1_5 = "This File Is Wrong! Please try it again!!" wide //weight: 1
        $x_1_6 = "Microsoft Visual Studio  is found A LOT BUG! Try to repair by attachments!" wide //weight: 1
        $x_1_7 = "The best important mend of Microsoft ,Please run the mend!!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Amend_A_2147602342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Amend.A"
        threat_id = "2147602342"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Amend"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "147"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 100
        $x_10_2 = "command.com /c net share C$=c:\\" wide //weight: 10
        $x_10_3 = "Outlook.Application" wide //weight: 10
        $x_10_4 = {3c 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 [0-4] 73 00 63 00 72 00 69 00 70 00 74 00 3e 00}  //weight: 10, accuracy: Low
        $x_1_5 = "TENCENT TRAVELER" wide //weight: 1
        $x_1_6 = "ctfmon.exe" wide //weight: 1
        $x_1_7 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_8 = "Folder.htt" wide //weight: 1
        $x_1_9 = "userinit.exe,regedit32.com" wide //weight: 1
        $x_1_10 = "\\system32\\notepad.exe" wide //weight: 1
        $x_1_11 = "cmd /c net localgroup administrators admin  /add" wide //weight: 1
        $x_1_12 = "NoDriveTypeAutoRun" wide //weight: 1
        $x_1_13 = "Kaspersky = Replace(Kaspersky, Chr(42), Chr(34))" wide //weight: 1
        $x_1_14 = "[autorun]" wide //weight: 1
        $x_1_15 = "Shellexecute=comand.com" wide //weight: 1
        $x_1_16 = "\\MicrosoftVisualStudio_BuG.rar" wide //weight: 1
        $x_1_17 = "\\MicrosoftVisualStudio_BuG.exe" wide //weight: 1
        $x_1_18 = "\\Gameprogram.pif" wide //weight: 1
        $x_1_19 = "\\ImportantFile.doc.exe" wide //weight: 1
        $x_1_20 = "\\Beautifulgirl.rar" wide //weight: 1
        $x_1_21 = "\\Accountaffirm.rar" wide //weight: 1
        $x_1_22 = "\\Gameprogram.rar" wide //weight: 1
        $x_1_23 = "\\ImportantFile.rar" wide //weight: 1
        $x_1_24 = "wintray.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 17 of ($x_1_*))) or
            (all of ($x*))
        )
}

