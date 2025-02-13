rule Virus_Win32_Fipeg_A_2147596445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Fipeg.gen!A"
        threat_id = "2147596445"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Fipeg"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_system~.ini" ascii //weight: 1
        $x_1_2 = "%s\\drivers" ascii //weight: 1
        $x_1_3 = "%s\\%s" ascii //weight: 1
        $x_1_4 = "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c" ascii //weight: 1
        $x_1_5 = ".~tmp" ascii //weight: 1
        $x_1_6 = "%s\\drivers\\%s" ascii //weight: 1
        $x_1_7 = "cmd.pif" ascii //weight: 1
        $x_1_8 = "MCI Program Com Application" ascii //weight: 1
        $x_1_9 = "shellexecute=page.pif" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

