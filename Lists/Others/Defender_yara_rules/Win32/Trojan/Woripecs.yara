rule Trojan_Win32_Woripecs_A_2147632233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Woripecs.gen!A"
        threat_id = "2147632233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Woripecs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 fa 50 74 38 6a 01 8d 4d e4 e8 ?? ?? ?? ?? 0f be 00 83 f8 4f 74 26 6a 02 8d 4d e4 e8 ?? ?? ?? ?? 0f be 08 83 f9 53 74 14 6a 03 8d 4d e4 e8 ?? ?? ?? ?? 0f be 10 83 fa 54 74 02}  //weight: 4, accuracy: Low
        $x_2_2 = "/isup.php" ascii //weight: 2
        $x_2_3 = "/setvar.php?key=" ascii //weight: 2
        $x_2_4 = "/hostname.php?host=" ascii //weight: 2
        $x_2_5 = "/checkport.php?port=%d&" ascii //weight: 2
        $x_1_6 = "DATAKEY:" ascii //weight: 1
        $x_1_7 = "THEFOOTERFILE:" ascii //weight: 1
        $x_1_8 = "%steal_login%" ascii //weight: 1
        $x_1_9 = "%no_auto_hosts%" ascii //weight: 1
        $x_1_10 = "%self_check_passed%" ascii //weight: 1
        $x_1_11 = "%escrow_ip%" ascii //weight: 1
        $x_1_12 = "%autoping%" ascii //weight: 1
        $x_1_13 = "%do_cpuinfo%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

