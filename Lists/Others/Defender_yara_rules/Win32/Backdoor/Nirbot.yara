rule Backdoor_Win32_Nirbot_2147582763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nirbot"
        threat_id = "2147582763"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nirbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 e8 03 00 00 b8 dc ff 00 00 e8 ?? ?? ?? ff 59 50 a3 ?? ?? ?? ?? 66 c7 ?? ?? ?? ?? 00 02 00 ff 15 ?? ?? ?? ?? 6a 10}  //weight: 10, accuracy: Low
        $x_8_2 = {8a 16 80 fa 2a 74 11 3a d1 74 05 80 fa 3f 75 26 46 40 8a 08 84 c9}  //weight: 8, accuracy: High
        $x_2_3 = "Bot Killed: %s" ascii //weight: 2
        $x_3_4 = "Scan: All Scan Threads Stopped. %d killed" ascii //weight: 3
        $x_2_5 = "Statistics: Exploits:" ascii //weight: 2
        $x_1_6 = "System: %s [CPU: %i x %s @ %dMhz]" ascii //weight: 1
        $x_1_7 = "%s HTTP: %d" ascii //weight: 1
        $x_1_8 = "%s; Daemons:" ascii //weight: 1
        $x_1_9 = "http://%s:%d/%s" ascii //weight: 1
        $x_1_10 = "Net: IP: %s Host: %s" ascii //weight: 1
        $x_2_11 = "Scan: Unknown Exploit." ascii //weight: 2
        $x_2_12 = "192.168.*.*" ascii //weight: 2
        $x_2_13 = "170.65.*.*" ascii //weight: 2
        $x_1_14 = "[OS: Microsoft Windows %s %s (%i.%i build %i)" ascii //weight: 1
        $x_1_15 = "HTTP: Transfer: %d.%d.%d.%d" ascii //weight: 1
        $x_2_16 = "if exist \"%s\" goto 1" ascii //weight: 2
        $x_2_17 = "scan.start" ascii //weight: 2
        $x_2_18 = "scan.stop" ascii //weight: 2
        $x_2_19 = "scan.stats" ascii //weight: 2
        $x_2_20 = "scn.bgn" ascii //weight: 2
        $x_2_21 = "scn.end" ascii //weight: 2
        $x_2_22 = "scn.stats" ascii //weight: 2
        $x_1_23 = "Windows NT4, 2000 (SP0-SP4)" ascii //weight: 1
        $x_2_24 = "Windows XP (SP0+SP1)" ascii //weight: 2
        $x_2_25 = "\\\\%s\\ipc$" ascii //weight: 2
        $x_2_26 = "\\\\%s\\pipe\\browser" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((10 of ($x_2_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 6 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

