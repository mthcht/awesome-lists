rule Backdoor_Win32_Oadway_A_2147957193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Oadway.A!dha"
        threat_id = "2147957193"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Oadway"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 fc 8b 4d f4 8b 14 81 8b 45 f8 8d 8c 10 dc 00 00 00 39 4d e4 77 02}  //weight: 10, accuracy: High
        $x_10_2 = {8b 55 fc 0f af 55 f8 8b 45 08 0f be 08 03 d1 89 55 fc 8b 55 08 83 c2 01 89 55 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Oadway_B_2147957194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Oadway.B!dha"
        threat_id = "2147957194"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Oadway"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "INJECTRUNNING \"%s\"" wide //weight: 5
        $x_5_2 = "Event_094180702090" wide //weight: 5
        $x_5_3 = "Mavinject.exe" wide //weight: 5
        $x_5_4 = "MicrosoftEdgeAutoLaunch_DAC5ED36BBAC4D19045B4BAFA91EF8729" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Oadway_C_2147957195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Oadway.C!dha"
        threat_id = "2147957195"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Oadway"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f be 08 83 f1 ?? 8b 55 08 03 55 f8 88 0a eb db}  //weight: 5, accuracy: Low
        $x_5_2 = {83 e0 47 31 f8 31 d8 81 f3 a0 00 00 00 21 fb 35 a4 00 00 00 09 c3 80 f3 c6}  //weight: 5, accuracy: High
        $x_5_3 = {88 d6 80 f6 ce 89 d3 80 e3 b0 80 f3 30 80 f2 7e 20 f2 08 da 88 14 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

