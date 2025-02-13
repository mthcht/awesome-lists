rule Trojan_Win32_Agramat_A_2147593900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agramat.A"
        threat_id = "2147593900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agramat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "You has been infected I repeat You has been infected and your system files has been deletes. Sorry" wide //weight: 10
        $x_10_2 = "SAPI.SpVoice" wide //weight: 10
        $x_10_3 = "I ProMise ... I Will Love YoU AlWayS BEa!" wide //weight: 10
        $x_10_4 = ":: Win32\\Hira.A - eCORE[GEDZAC] - I AlwAyS WilL LoVE YoU BeA ::" wide //weight: 10
        $x_1_5 = "\\shell\\open\\command" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

