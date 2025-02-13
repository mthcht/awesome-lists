rule Backdoor_Win32_Stealbot_2147596539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Stealbot"
        threat_id = "2147596539"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "130"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {c6 02 00 03 d0 4f 75 f8 eb 01 41 80 39 20 74 fa 8a 11 80 fa 20 74 17 33 ff 84 d2 74 11 83 ff 0f 7d 0c 88 16 46 47 41 8a 11 80 fa 20 75 eb 33 ff c6 06 00 89 7d 0c eb 01 41 80 39 20 74 fa 8a 19 84 db 74 7e 8b 55 10 03 d7 80 fb 22 75 3b 41 80 39 22 74 fa 8a 19 84 db 74 68 80 fb 22 74 22 8b f2 2b f7 2b 75 10 b8 00 01 00 00 84 db 74 13 3b f0 7d 0f 88 1a 42 46 41 8a 19 80 fb 22 75 ec eb 01 41 80 39 22 74 fa eb 25 80 fb 20 74 20 8b f2 2b f7 2b 75 10 b8 00 01 00 00 84 db 74 10 3b f0 7d 0c 88 1a 42 46 41 8a 19 80 fb 20 75 ec ff 45 0c 03 f8 81 ff 00 0a 00 00 c6 02 00 0f 8c 77 ff ff ff 8b 45 0c}  //weight: 100, accuracy: High
        $x_10_2 = "drivers\\etc\\hosts" ascii //weight: 10
        $x_10_3 = "Hardware\\Description\\System\\CentralProcessor\\0" ascii //weight: 10
        $x_10_4 = {31 37 32 2e 31 36 00 00 31 39 32 2e 31 36 38 00}  //weight: 10, accuracy: High
        $x_1_5 = "application/octet-stream" ascii //weight: 1
        $x_1_6 = "<td align=\"right\">%dKb</td>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

