rule Worm_Win32_Colowned_A_2147643064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Colowned.A"
        threat_id = "2147643064"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Colowned"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "addtostartup%%o<main.main>" ascii //weight: 1
        $x_1_2 = "doupdate%b%o<main.main>" ascii //weight: 1
        $x_1_3 = "install%%o<main.main>" ascii //weight: 1
        $x_1_4 = "checkifnew%%o<main.main>" ascii //weight: 1
        $x_1_5 = "send%%o<ircx>" ascii //weight: 1
        $x_1_6 = "parsedata%%o<ircx>" ascii //weight: 1
        $x_1_7 = "privmsg%%o<ircx>" ascii //weight: 1
        $x_1_8 = "infect%%o<usb>" ascii //weight: 1
        $x_1_9 = "trycopy%b%o<usb>" ascii //weight: 1
        $x_1_10 = "goVisit%%o<getcmd>" ascii //weight: 1
        $x_1_11 = "initpayload%%o<spl>" ascii //weight: 1
        $x_1_12 = "scanlocal 445 40" ascii //weight: 1
        $x_1_13 = "scanmyrange 445 40" ascii //weight: 1
        $x_1_14 = "%tmp%&cd framework&winshell.bat" ascii //weight: 1
        $x_1_15 = "%appdata%&cd framework3&winshell.bat" ascii //weight: 1
        $x_2_16 = "i&echo get sysup.exe>>i&echo bye>>i&ftp -s:i&start" ascii //weight: 2
        $x_1_17 = "mmutex%o<Mutex>%" ascii //weight: 1
        $x_1_18 = "upgrade_action%%o<main.main>" ascii //weight: 1
        $x_1_19 = "drivetype%s%o<usb>s" ascii //weight: 1
        $x_2_20 = {75 70 64 61 74 65 66 75 63 6b 65 72 75 70 64 61 74 65 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

