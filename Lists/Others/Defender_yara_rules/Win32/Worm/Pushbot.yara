rule Worm_Win32_Pushbot_113259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pushbot"
        threat_id = "113259"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pushbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "msn.spread" ascii //weight: 5
        $x_5_2 = "%s Kill: <%d> threads" ascii //weight: 5
        $x_5_3 = "%s Bot installed on: %s." ascii //weight: 5
        $x_5_4 = "%s Spy: %s!%s@%s (PM: \"%s\")" ascii //weight: 5
        $x_1_5 = "JOIN %s" ascii //weight: 1
        $x_1_6 = "PRIVMSG %s" ascii //weight: 1
        $x_1_7 = "del \"%s\">nul" ascii //weight: 1
        $x_1_8 = "del \"%%0\"" ascii //weight: 1
        $x_1_9 = "ping 0.0.0.0>nul" ascii //weight: 1
        $x_1_10 = "if exist \"%s\" goto Repeat" ascii //weight: 1
        $x_1_11 = "%s\\removeMe%i%i%i%i.bat" ascii //weight: 1
        $x_1_12 = "socket" ascii //weight: 1
        $x_1_13 = "InternetOpen" ascii //weight: 1
        $x_1_14 = "InternetReadFile" ascii //weight: 1
        $x_1_15 = "InternetConnectA" ascii //weight: 1
        $x_1_16 = "msnmsgs.exe" ascii //weight: 1
        $x_1_17 = "*!*@boss.gov" ascii //weight: 1
        $x_1_18 = "aryan.opendns.be" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 10 of ($x_1_*))) or
            ((4 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Pushbot_B_115943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pushbot.gen!B"
        threat_id = "115943"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pushbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VNC Scanning Bot" ascii //weight: 1
        $x_1_2 = "RFB 003.008" ascii //weight: 1
        $x_1_3 = "[MAIN]" ascii //weight: 1
        $x_1_4 = "RXBot" ascii //weight: 1
        $x_1_5 = "[SCAN]" ascii //weight: 1
        $x_1_6 = "[FTP]" ascii //weight: 1
        $x_1_7 = "scan.stop" ascii //weight: 1
        $x_1_8 = "NZM/ST" ascii //weight: 1
        $x_1_9 = "scanall" ascii //weight: 1
        $x_1_10 = "YaBot" ascii //weight: 1
        $x_20_11 = {59 85 c0 59 74 1b 81 ec 28 01 00 00 8d 75 ?? 6a 4a 59 8b fc f3 a5 e8 ?? ?? ?? ?? 81 c4 28 01 00 00 83 c3 08 8b c3 83 3b 00 75 ?? b9 00 14 00 00}  //weight: 20, accuracy: Low
        $x_15_12 = {6a 00 6a 04 8d 45 ?? 50 6a 07 ff 75 08 ff 55 ?? 85 c0 75 0a 83 7d ?? 00 74 04 b0 01 eb 02}  //weight: 15, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 5 of ($x_1_*))) or
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Pushbot_C_116276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pushbot.gen!C"
        threat_id = "116276"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pushbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ddos.syn" ascii //weight: 1
        $x_1_2 = "ddos.ack" ascii //weight: 1
        $x_1_3 = "ddos.random" ascii //weight: 1
        $x_1_4 = ".download" ascii //weight: 1
        $x_1_5 = {2e 75 70 64 (61|34) 74 65}  //weight: 1, accuracy: Low
        $x_1_6 = "msn.spread" ascii //weight: 1
        $x_1_7 = "msn.msg" ascii //weight: 1
        $x_1_8 = "msn.stats" ascii //weight: 1
        $x_1_9 = "ms.stats" ascii //weight: 1
        $x_1_10 = "scan.stop" ascii //weight: 1
        $x_1_11 = "scan.start" ascii //weight: 1
        $x_1_12 = "botkiller.start" ascii //weight: 1
        $x_1_13 = "aim.msg" ascii //weight: 1
        $x_1_14 = "triton.msg" ascii //weight: 1
        $x_1_15 = "pstore.search" ascii //weight: 1
        $x_1_16 = "supersyn.stop" ascii //weight: 1
        $x_1_17 = "dl.start" ascii //weight: 1
        $x_1_18 = "dl.stop" ascii //weight: 1
        $x_1_19 = "kill.bot" ascii //weight: 1
        $x_1_20 = "msn.spam" ascii //weight: 1
        $x_1_21 = "msn.file" ascii //weight: 1
        $x_1_22 = "msn.stop" ascii //weight: 1
        $x_1_23 = "Failed to start dl thread." ascii //weight: 1
        $x_1_24 = "%s %s \"\" \"lol\" :%s" ascii //weight: 1
        $x_1_25 = "%s %s * 0 :%s" ascii //weight: 1
        $x_1_26 = "%s:*:Enabled:%s" ascii //weight: 1
        $x_1_27 = "oto :D %s" ascii //weight: 1
        $x_1_28 = {5b 47 45 54 5d 3a 20 ?? 20 25 73 20 74 6f 3a 20 25 73}  //weight: 1, accuracy: Low
        $x_1_29 = {46 69 6c 65 20 72 75 6e 6e 69 6e 67 3a 20 ?? 20 00}  //weight: 1, accuracy: Low
        $x_3_30 = {6d 47 fe 74 e8 bf c2 45 90 35 d1 5e 33 0a 24 6d}  //weight: 3, accuracy: High
        $x_6_31 = "[Msn]: Message sent." ascii //weight: 6
        $x_6_32 = {49 20 74 72 69 65 64 20 74 6f 20 66 6f 6f 6c 20 25 64 20 6d 6f 72 6f 6e 73 2e 00}  //weight: 6, accuracy: High
        $x_6_33 = "Msn Message sent to %d nigg" ascii //weight: 6
        $x_1_34 = "USB|%s|%s|%s|%s" ascii //weight: 1
        $x_1_35 = "Supersyn Attack Active!" ascii //weight: 1
        $x_1_36 = "Nig Bot v" ascii //weight: 1
        $x_6_37 = {54 53 6b 79 70 65 53 70 6c 69 74 74 65 72 00 00 54 43 6f 6e 76 65 72 73 61 74 69 6f 6e 73 43 6f 6e 74 72 6f 6c 00 00 00 41 54 4c 00 59 61 68 6f 6f 42 75 64 64 79 4d 61 69 6e}  //weight: 6, accuracy: High
        $x_2_38 = {53 4b 59 50 45 2e 74 78 74 00 00 00 43 6c 6f 73 69 6e 67 20 49 4d 20 57 69 6e 64 6f 77 00 00 00 5f 5f 6f 78 46 72 61 6d 65 2e 63 6c 61 73 73 5f 5f}  //weight: 2, accuracy: High
        $x_1_39 = {00 42 6c 61 73 74 20 49 4d 00}  //weight: 1, accuracy: High
        $x_2_40 = {5b 25 73 7c 25 73 5d 25 73 00 [0-3] 6e 5b 25 73 7c 25 73 5d 25 73}  //weight: 2, accuracy: Low
        $x_1_41 = "ass off! Here you go: http:" ascii //weight: 1
        $x_1_42 = {25 73 5c 25 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_43 = {50 52 49 56 4d 53 47 00}  //weight: 1, accuracy: High
        $x_1_44 = "/ajax/chat/buddy_list.php?__a=1" ascii //weight: 1
        $x_40_45 = {56 6a 01 56 6a 11 ff d3 56 56 56 6a 56 ?? ?? ?? ?? ?? ?? 50 ff d3 56 6a 03 6a 2d 6a 11 ff d3}  //weight: 40, accuracy: Low
        $x_40_46 = {59 59 6a 00 6a 01 6a 00 6a 11 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 56 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 6a 00 6a 03 6a 2d 6a 11 ff 15 ?? ?? ?? ?? (83 bd ?? ?? ff ff 00 75 ?? 6a 32|6a 00 6a 00 6a 00 6a 0d ff 15 ?? ?? ?? ?? 6a 32)}  //weight: 40, accuracy: Low
        $x_40_47 = {56 6a 01 56 6a 11 ff d3 8b 3d ?? ?? ?? ?? 56 56 56 6a 56 ff d7 (50|0f b6) ff d3 56 6a 03 6a 2d 6a 11 ff d3}  //weight: 40, accuracy: Low
        $x_40_48 = {6a 00 6a 01 6a 00 6a 11 (ff 15 ?? ?? ?? ??|e8 ?? ?? ?? ?? ??) 6a 00 6a 00 6a 00 6a 56 (ff 15 ?? ?? ?? ??|e8 ?? ?? ?? ?? ??) 50 (ff 15 ?? ?? ?? ??|e8 ?? ?? ?? ?? ??) 6a 00 6a 03 6a 2d 6a 11 (ff 15 ?? ?? ?? ??|e8 ?? ?? ?? ?? ??) 6a 00 6a 00 6a 00 6a 0d}  //weight: 40, accuracy: Low
        $x_40_49 = {6a 00 6a 01 6a 00 6a 11 ff d6 6a 00 6a 00 6a 00 6a 56 ff 15 ?? ?? ?? ?? 0f b6 d0 52 ff d6 6a 00 6a 03 6a 2d 6a 11 ff d6 6a 00 6a 00 6a 00 6a 0d ff d6}  //weight: 40, accuracy: Low
        $x_3_50 = {3b d0 75 4f 8b 8d 00 fb ff ff 83 c1 01 89 8d 00 fb ff ff 8b 55 18 52 83 ec 34 b9 0d 00 00 00 8d b5 c4 fa ff ff}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 36 of ($x_1_*))) or
            ((2 of ($x_3_*) and 37 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 35 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 33 of ($x_1_*))) or
            ((1 of ($x_6_*) and 37 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 35 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*) and 33 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 34 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 32 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 30 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 31 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 29 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 27 of ($x_1_*))) or
            ((2 of ($x_6_*) and 31 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_2_*) and 29 of ($x_1_*))) or
            ((2 of ($x_6_*) and 2 of ($x_2_*) and 27 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 28 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 26 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 24 of ($x_1_*))) or
            ((2 of ($x_6_*) and 2 of ($x_3_*) and 25 of ($x_1_*))) or
            ((2 of ($x_6_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 23 of ($x_1_*))) or
            ((2 of ($x_6_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 21 of ($x_1_*))) or
            ((3 of ($x_6_*) and 25 of ($x_1_*))) or
            ((3 of ($x_6_*) and 1 of ($x_2_*) and 23 of ($x_1_*))) or
            ((3 of ($x_6_*) and 2 of ($x_2_*) and 21 of ($x_1_*))) or
            ((3 of ($x_6_*) and 1 of ($x_3_*) and 22 of ($x_1_*))) or
            ((3 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 20 of ($x_1_*))) or
            ((3 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 18 of ($x_1_*))) or
            ((3 of ($x_6_*) and 2 of ($x_3_*) and 19 of ($x_1_*))) or
            ((3 of ($x_6_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 17 of ($x_1_*))) or
            ((3 of ($x_6_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 15 of ($x_1_*))) or
            ((4 of ($x_6_*) and 19 of ($x_1_*))) or
            ((4 of ($x_6_*) and 1 of ($x_2_*) and 17 of ($x_1_*))) or
            ((4 of ($x_6_*) and 2 of ($x_2_*) and 15 of ($x_1_*))) or
            ((4 of ($x_6_*) and 1 of ($x_3_*) and 16 of ($x_1_*))) or
            ((4 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((4 of ($x_6_*) and 2 of ($x_3_*) and 13 of ($x_1_*))) or
            ((4 of ($x_6_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((4 of ($x_6_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_40_*) and 3 of ($x_1_*))) or
            ((1 of ($x_40_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_40_*) and 2 of ($x_2_*))) or
            ((1 of ($x_40_*) and 1 of ($x_3_*))) or
            ((1 of ($x_40_*) and 1 of ($x_6_*))) or
            ((2 of ($x_40_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Pushbot_E_123885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pushbot.gen!E"
        threat_id = "123885"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pushbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " Message sent to: %d Contacts." ascii //weight: 1
        $x_1_2 = " message sent to %d losers." ascii //weight: 1
        $x_1_3 = "I tried to fool %d morons." ascii //weight: 1
        $x_10_4 = {83 f8 01 7e 25 50 a1 ?? ?? ?? ?? 69 c0 ?? 01 00 00 (05 ?? ?? ?? ?? 68 ?? ?? ?? ??|68 ?? ?? ?? ?? 05 ?? ?? ?? ??) 50 ff b5 ?? ?? ff ff e8}  //weight: 10, accuracy: Low
        $x_10_5 = {83 f8 01 7e 1d 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 50 ff 75 00 e8}  //weight: 10, accuracy: Low
        $x_10_6 = {69 c0 60 01 00 00 05 ?? ?? ?? ?? 50 ff b5 ?? ?? ff ff e8 19 00 83 3d ?? ?? ?? ?? 01 7e ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? a1}  //weight: 10, accuracy: Low
        $x_10_7 = {00 01 7e 1e ff 35 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 ff b5 ?? ?? ff ff e8 05 00 83 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Pushbot_SW_152705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pushbot.SW"
        threat_id = "152705"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pushbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 1c 08 0f b6 14 0a 01 d3 89 da 81 e2 00 03 00 00 29 d3 0f b6 04 19 30 04 3e 46}  //weight: 1, accuracy: Low
        $x_1_2 = "net stop MsMpSvc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Pushbot_UI_158110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pushbot.UI"
        threat_id = "158110"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pushbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Users\\hex\\AppData\\Local\\Temp\\Travelerz\\VB6.OLB" ascii //weight: 1
        $x_1_2 = "Salmandos" ascii //weight: 1
        $x_1_3 = {fc 06 00 00 c7 45 fc ?? 00 00 00 c7 85 ?? ?? ff ff ?? ?? 40 00 c7 85 ?? fe ff ff 08 00 00 00 8d ?? ?? ?? 8d ?? ?? fe ff ff ?? 8d ?? ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Pushbot_UJ_158192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pushbot.UJ"
        threat_id = "158192"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pushbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s %s \"\" \"lol\" :%s" ascii //weight: 1
        $x_1_2 = "BotPoke" ascii //weight: 1
        $x_1_3 = "scan.stop" ascii //weight: 1
        $x_1_4 = "msnhiddenwindowclass" ascii //weight: 1
        $x_1_5 = {5b 61 75 74 6f 72 75 6e 5d 00}  //weight: 1, accuracy: High
        $x_1_6 = "action=open folder to view files" ascii //weight: 1
        $x_1_7 = {00 64 64 6f 73 65 72 00}  //weight: 1, accuracy: High
        $x_1_8 = "\\RECYCLER" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Worm_Win32_Pushbot_VJ_170884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pushbot.VJ"
        threat_id = "170884"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pushbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&msg_text=%s&to_offline=false&post_form_id=" ascii //weight: 1
        $x_1_2 = {6a 00 6a 03 6a 2d 6a 11 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 0d ff 15 00 8b 85 ?? ?? ff ff 8b 08 8b 95 02 ff ff 52 ff 51 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Pushbot_VR_174208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pushbot.VR"
        threat_id = "174208"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pushbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "330"
        strings_accuracy = "Low"
    strings:
        $x_200_1 = {80 75 08 66 80 75 09 c8 f6 55 0a 80 75 0b 3f 8b 45 08 5d}  //weight: 200, accuracy: High
        $x_50_2 = {7e 10 03 c6 80 30 66 ff 45 fc 8b 45 fc 3b 45 ec 7c f0 88 1c 30}  //weight: 50, accuracy: High
        $x_30_3 = "xhpc_composerid=u512260_3&xhpc_context=home&xhpc" ascii //weight: 30
        $x_30_4 = "MMAP_AV_{7E63D6E6-5711-480d-99A0-C3972C93EEF4}" ascii //weight: 30
        $x_20_5 = "batch[0][timestamp]=1333995680955" ascii //weight: 20
        $x_20_6 = "-1782695666%40mail.projektitan.com" ascii //weight: 20
        $x_20_7 = "client_time=1304680030823" ascii //weight: 20
        $x_10_8 = "/me/friends?access_token=" ascii //weight: 10
        $x_10_9 = "tweak.tomdzon.com" ascii //weight: 10
        $x_10_10 = "SkypeControlAPIDiscover" ascii //weight: 10
        $x_20_11 = {68 39 36 7d 4a e8 ?? ff ff ff 59 85 c0 77 12 68 e6 02 3f e3}  //weight: 20, accuracy: Low
        $x_20_12 = {68 d1 b1 a0 f8 e8 ?? ff ff ff 59 85 c0 77 21 68 80 e1 c7 a6}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_200_*) and 5 of ($x_20_*) and 3 of ($x_10_*))) or
            ((1 of ($x_200_*) and 1 of ($x_30_*) and 4 of ($x_20_*) and 2 of ($x_10_*))) or
            ((1 of ($x_200_*) and 1 of ($x_30_*) and 5 of ($x_20_*))) or
            ((1 of ($x_200_*) and 2 of ($x_30_*) and 2 of ($x_20_*) and 3 of ($x_10_*))) or
            ((1 of ($x_200_*) and 2 of ($x_30_*) and 3 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_200_*) and 2 of ($x_30_*) and 4 of ($x_20_*))) or
            ((1 of ($x_200_*) and 1 of ($x_50_*) and 3 of ($x_20_*) and 2 of ($x_10_*))) or
            ((1 of ($x_200_*) and 1 of ($x_50_*) and 4 of ($x_20_*))) or
            ((1 of ($x_200_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 1 of ($x_20_*) and 3 of ($x_10_*))) or
            ((1 of ($x_200_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 2 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_200_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 3 of ($x_20_*))) or
            ((1 of ($x_200_*) and 1 of ($x_50_*) and 2 of ($x_30_*) and 2 of ($x_10_*))) or
            ((1 of ($x_200_*) and 1 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Pushbot_VV_180122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pushbot.VV"
        threat_id = "180122"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pushbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 83 f8 41 74 32 66 83 f8 42 74 2c 66 83 f8 61 74 26 66 83 f8 62 74 20 8d 45 f8 50 ff d7 83 f8 02 74 0b 8d 45 f8 50 ff d7 83 f8 04}  //weight: 2, accuracy: High
        $x_1_2 = {8a 04 37 33 c9 32 81 ?? ?? 40 00 41 88 04 37 81 f9 00 01 00 00 72 ee 83 3d ?? ?? 40 00 00 74 05 f6 d0 88 04 37}  //weight: 1, accuracy: Low
        $x_1_3 = "About to kill = [%ls], Pid = [%d], GetLastError() = [%u]" ascii //weight: 1
        $x_1_4 = "Spreader Enabled, Interval = [%d], Message = [%s]" ascii //weight: 1
        $x_1_5 = "Infected %d folder(s), last folder infected: [ %ls ]" ascii //weight: 1
        $x_1_6 = {53 75 70 65 72 53 79 6e 00 00 00 00 41 74 74 61 63 6b 20 4f 6e 20 25 73 3a 25 69 20 43 6f 6d 70 6c 65 74 65 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

