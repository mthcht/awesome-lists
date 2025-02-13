rule Backdoor_Win32_Phostiko_A_2147602779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Phostiko.gen!A"
        threat_id = "2147602779"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Phostiko"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 10
        $x_3_2 = {80 bb 0a 03 00 00 00 75 47 c6 06 00 8b c3 e8 92 cb fd ff 8b 83 f0 02 00 00 8b 80 90 00 00 00 e8 71 3f fe ff 48 78 67 8b 83 f0 02 00 00 8b b0 90 00 00 00}  //weight: 3, accuracy: High
        $x_1_3 = "Hei..! who are you?" ascii //weight: 1
        $x_1_4 = "8zero8x2" ascii //weight: 1
        $x_1_5 = "I kick u..." ascii //weight: 1
        $x_1_6 = "hostipok" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

