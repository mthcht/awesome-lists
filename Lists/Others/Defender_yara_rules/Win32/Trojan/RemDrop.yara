rule Trojan_Win32_RemDrop_2147748544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemDrop!MTB"
        threat_id = "2147748544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemDrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ADMQCMD" wide //weight: 1
        $x_1_2 = "CABINET" wide //weight: 1
        $x_1_3 = "EXTRACTOPT" wide //weight: 1
        $x_1_4 = "FILESIZES" wide //weight: 1
        $x_1_5 = "FINISHMSG" wide //weight: 1
        $x_1_6 = "LICENSE" wide //weight: 1
        $x_1_7 = "PACKINSTSPACE" wide //weight: 1
        $x_1_8 = "POSTRUNPROGRAM" wide //weight: 1
        $x_1_9 = "REBOOT" wide //weight: 1
        $x_1_10 = "RUNPROGRAM" wide //weight: 1
        $x_1_11 = "SHOWWINDOW" wide //weight: 1
        $x_1_12 = "UPROMPT" wide //weight: 1
        $x_1_13 = "USRQCMD" wide //weight: 1
        $x_1_14 = "stealth_thing.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

