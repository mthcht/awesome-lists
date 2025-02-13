rule Backdoor_Win32_Spybot_2147602566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spybot"
        threat_id = "2147602566"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spybot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "!killthread" ascii //weight: 1
        $x_1_2 = "!killproc" ascii //weight: 1
        $x_1_3 = "!redirectme" ascii //weight: 1
        $x_1_4 = "!redspy" ascii //weight: 1
        $x_1_5 = "!killclones" ascii //weight: 1
        $x_1_6 = "!startlog" ascii //weight: 1
        $x_1_7 = "!opencmd" ascii //weight: 1
        $x_1_8 = "!ntstats" ascii //weight: 1
        $x_1_9 = "riffraff" ascii //weight: 1
        $x_1_10 = "windozexp" ascii //weight: 1
        $x_1_11 = "ihavenopass" ascii //weight: 1
        $x_1_12 = "[Print Screen]" ascii //weight: 1
        $x_2_13 = "h4x0ring" ascii //weight: 2
        $x_2_14 = "href=\"%s%s\">%s</A>" ascii //weight: 2
        $x_2_15 = "Bot Version:" ascii //weight: 2
        $x_2_16 = "%s\\Admin$" ascii //weight: 2
        $x_2_17 = "%s\\c$\\winnt" ascii //weight: 2
        $x_3_18 = "Exploited %d Systems" ascii //weight: 3
        $x_3_19 = "listin port: %i" ascii //weight: 3
        $x_3_20 = "Searsing for passwords" ascii //weight: 3
        $x_3_21 = {4e 65 74 55 73 65 72 45 6e 75 6d 00 4e 65 74 52 65 6d 6f 74 65 54 4f 44 00 4e 65 74 53 63 68 65 64}  //weight: 3, accuracy: High
        $x_3_22 = {25 73 5c 69 70 63 24 00 5b 4e 55 4c 4c 5d}  //weight: 3, accuracy: High
        $x_3_23 = "PRIVMSG %s :Port %i" ascii //weight: 3
        $x_3_24 = "stopkeylogger\" to stop" ascii //weight: 3
        $x_10_25 = {b9 3c 00 00 00 ba 89 88 88 88 f7 e2 c1 ea 05}  //weight: 10, accuracy: High
        $x_10_26 = {b9 a0 05 00 00 31 d2 f7 f1 89 95 ?? ?? ?? ff b8 60 ea 00 00 f7 a5}  //weight: 10, accuracy: Low
        $x_10_27 = {59 31 f6 eb 1c e8 ?? ?? ?? 00 b9 1a 00 00 00 99 f7 f9 89 d7 83 c7 61 89 fa 88 14 35}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 10 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_3_*) and 7 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((4 of ($x_3_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((5 of ($x_3_*) and 1 of ($x_1_*))) or
            ((5 of ($x_3_*) and 1 of ($x_2_*))) or
            ((6 of ($x_3_*))) or
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Spybot_B_2147602642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spybot.gen!B"
        threat_id = "2147602642"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spybot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 1a 00 00 00 99 f7 f9 89 d7 83 c7 61 89 fa 88 14 35 ?? ?? ?? ?? 46 8d 0d ?? ?? ?? ?? 83 c8 ff 40 80 3c 01 00 75 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {86 00 74 70 67 75 78 62 73 66 7d 6e 8a 84 93 90 94 90 87 95}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

