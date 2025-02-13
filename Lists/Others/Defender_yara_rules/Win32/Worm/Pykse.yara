rule Worm_Win32_Pykse_A_2147594105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pykse.A"
        threat_id = "2147594105"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pykse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "USB: user interactive file copied to usb." ascii //weight: 1
        $x_1_2 = "USB: hidden trojan file copied to usb." ascii //weight: 1
        $x_1_3 = "Unknown security failure detected!" ascii //weight: 1
        $x_1_4 = "USB: autorun file copied to usb." ascii //weight: 1
        $x_1_5 = "Mutex already exsist. exit." ascii //weight: 1
        $x_1_6 = "Skype Worm server mutex1" ascii //weight: 1
        $x_1_7 = "Removing all old shit" ascii //weight: 1
        $x_1_8 = "Getting premissions" ascii //weight: 1
        $x_1_9 = "drivers\\etc\\hosts" ascii //weight: 1
        $x_1_10 = "Software\\Pykse2\\" ascii //weight: 1
        $x_1_11 = "c:\\log.doc" ascii //weight: 1
        $x_1_12 = "zjbs.exe" ascii //weight: 1
        $x_1_13 = "game.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Worm_Win32_Pykse_B_2147596292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pykse.B"
        threat_id = "2147596292"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pykse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SET USERSTATUS" ascii //weight: 1
        $x_1_2 = "USERS" ascii //weight: 1
        $x_1_3 = "ONLINESTATUS" ascii //weight: 1
        $x_1_4 = "SEARCH FRIENDS" ascii //weight: 1
        $x_2_5 = "Skype-API-Ctrl" ascii //weight: 2
        $x_2_6 = "SkypeControlAPI" ascii //weight: 2
        $x_3_7 = "Skype Worm" ascii //weight: 3
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_3_9 = "MESSAGE %s %s" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

