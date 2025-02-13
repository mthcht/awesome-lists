rule Worm_Win32_Skopvel_A_2147641204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Skopvel.gen!A"
        threat_id = "2147641204"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Skopvel"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "COMUNE2.0BYPLAYSKOOL" wide //weight: 1
        $x_1_2 = "C:\\lovely.ini" wide //weight: 1
        $x_1_3 = "logdata=RAR archives infected" wide //weight: 1
        $x_1_4 = "logdata=Infected from USB drive" wide //weight: 1
        $x_1_5 = "logdata=Infected LAN Computers" wide //weight: 1
        $x_1_6 = "logdata=Downloaded payload" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

