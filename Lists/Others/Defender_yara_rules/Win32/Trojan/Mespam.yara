rule Trojan_Win32_Mespam_A_2147576479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mespam.A"
        threat_id = "2147576479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mespam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sporder.dll" ascii //weight: 2
        $x_3_2 = "SOFTWARE\\WinSock2\\Buibert" ascii //weight: 3
        $x_3_3 = "rsvp32_2.dll" ascii //weight: 3
        $x_1_4 = "WSCWriteProviderOrder" ascii //weight: 1
        $x_1_5 = "gobmccpsmrmggcomcenldrg" ascii //weight: 1
        $x_1_6 = "nrlqomhqibqjsqderqpkghlrk" ascii //weight: 1
        $x_1_7 = "hsebnfmsqijorfjooonckehpdp" ascii //weight: 1
        $x_1_8 = "kdgfjeqssgblbshgmdehdibeppq" ascii //weight: 1
        $x_1_9 = "ksbsskeenmigkbcfhjjerfmgbddin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Mespam_B_2147580881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mespam.B"
        threat_id = "2147580881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mespam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JabberEngine" ascii //weight: 1
        $x_1_2 = "MESSAGE WITH ADV TEXT SENDED" ascii //weight: 1
        $x_1_3 = "body ok" ascii //weight: 1
        $x_1_4 = "ssage to=\"" ascii //weight: 1
        $x_1_5 = "Packet len >" ascii //weight: 1
        $x_1_6 = "Packet From user" ascii //weight: 1
        $x_1_7 = "zu2/zc.php" ascii //weight: 1
        $x_1_8 = "?l=%s&d=%s&v=%s" ascii //weight: 1
        $x_1_9 = "smtspm" ascii //weight: 1
        $x_1_10 = "ERT TEXT to:" ascii //weight: 1
        $x_1_11 = "&msg_body=" ascii //weight: 1
        $x_1_12 = "/newthread.php?do=postthread" ascii //weight: 1
        $x_1_13 = "i?mode=compose" ascii //weight: 1
        $x_1_14 = "CONTACT TO::::>>>" ascii //weight: 1
        $x_1_15 = "rvz1=%d&rvz2=%" ascii //weight: 1
        $x_1_16 = "&fldBody=" ascii //weight: 1
        $x_1_17 = "htmlcompose/c_compose" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule Trojan_Win32_Mespam_C_2147583606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mespam.C!dll"
        threat_id = "2147583606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mespam"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Layered Provider Async Window" ascii //weight: 1
        $x_1_2 = "CJabberTalk::" ascii //weight: 1
        $x_1_3 = "MESSAGE WITH ADV TEXT SENDED" ascii //weight: 1
        $x_1_4 = "contact ok" ascii //weight: 1
        $x_1_5 = "body ok" ascii //weight: 1
        $x_1_6 = "msgto found" ascii //weight: 1
        $x_1_7 = "Packet len > 100 and adv_txt >3" ascii //weight: 1
        $x_1_8 = "Packet From user" ascii //weight: 1
        $x_1_9 = "zc.php" ascii //weight: 1
        $x_1_10 = "gtalk" ascii //weight: 1
        $x_1_11 = "Cuni_ICQv7::" ascii //weight: 1
        $x_1_12 = "Sending ADVERT TEXT to:" ascii //weight: 1
        $x_1_13 = "CYahooMsg:: " ascii //weight: 1
        $x_1_14 = "CONTACT TO::::>>>" ascii //weight: 1
        $x_1_15 = "aosmx.dll" ascii //weight: 1
        $x_1_16 = "aimsmx.dll" ascii //weight: 1
        $x_1_17 = "ymsgsmx.dll" ascii //weight: 1
        $x_1_18 = "gtalsmx.dll" ascii //weight: 1
        $x_1_19 = "smtsmxpfx.dll" ascii //weight: 1
        $x_1_20 = "smtsmx.dll" ascii //weight: 1
        $x_1_21 = "spmsmtsmxpfx.dll" ascii //weight: 1
        $x_1_22 = "spmsmtsmx.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (17 of ($x*))
}

rule Trojan_Win32_Mespam_2147598687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mespam!dr"
        threat_id = "2147598687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mespam"
        severity = "Critical"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 45 00 00 4c 01 02 00 9b 74 e0 45 00 00 00 00 00 00 00 00 e0 00 0f 01 0b 01 06 00 00 22 00 00 00 5c 01 00 00 00 00 00 00 10 00 00 00 10 00 00 00 40 00 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 b0 01 00 00 04 00 00 00 00 00 00 02 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 89 e5 68 2a 02 00 00 50 e8 17 00 00 00 5d eb 43 81 c5 ff 63 fe ff f7 d5 01 dd 89 ef 81 c7 dc 07 00 00 eb 12 92 83 c4 0c 5d eb 52 83 c4 0c 56 53 55 57 31 ed eb d8 e8 4e 00 00 00 85 c9 75 f7 eb 66 e8 03 00 00 00 59 50 c3 59 5e 5b 5d 5f e8 f3 ff ff ff 52 e8 00 00 00 00 5b 66 31 db 8b 13 81 f2 77 44 aa ff 66 81 fa 3a 1e 74 0e 8d 9b 00 f0 00 f5 81 c3 00 f0 af 00 eb e3 5a eb 93 68 aa aa ff 7f 6a 00 e8 a2 ff ff ff ba 08 a4 01 00 8b 04 1a 6a 00 ff d0 8d 88 ae de d7 da 01 4d 00 8d 6c 05 05 89 f9 29 e9 c3 81 ef dc 07 00 00 89 f8 eb 90}  //weight: 1, accuracy: High
        $x_1_3 = {01 83 88 c1 27 40 00 61 16 b8 07 fd 2d 21 30 85 15 6c 4e 13 32 49 02 d8 99 26 40 00 52 62 a3 23 6e 21 d5 e4 2a fc 28 d3 78 5e 77 75 73 6f 63 41 b7 33 79 62 a1 94 d6 03 2b fc 28 d3 31 f9 02 7a 8a e5 83 ec 5b 96 4c f5 2d 21 d6 03 f2 41 24 d4 31 f9 02 85 8c 75 08 03 c9 0b 16 b4 84 27 20 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mespam_A_2147603216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mespam.gen!A"
        threat_id = "2147603216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mespam"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 07 3c 45 75 12 80 7f 01 48 75 0c 80 7f 02 4c 75 06 80 7f 03 4f 74 d3 3c 48 75 12 80 7f 01 45 75 0c 80 7f 02 4c 75 06 80 7f 03 4f 74 bd 3b cb 75 32 83 7d 10 06 75 20 80 3f 44 75 1b 80 7f 01 41 75 15 80 7f 02 54 75 0f 80 7f 03 41 75 09}  //weight: 10, accuracy: High
        $x_10_2 = {80 3e 59 0f 85 e4 02 00 00 80 7e 01 4d 0f 85 da 02 00 00 80 7e 02 53 0f 85 d0 02 00 00 80 7e 03 47 0f 85 c6 02 00 00 89 73 34 66 8b 46 04 89 45 e4 8d 45 e4 50}  //weight: 10, accuracy: High
        $x_10_3 = {80 3c 06 c0 75 1c 80 7c 06 01 80 75 15 80 7c 06 02 35 75 0e 80 7c 06 03 c0 75 07 80 7c 06 04 80 74 07 40 3b c7 72 d9 eb 5b 8d 48 06 80 3c 0e c0 75 07 80 7c 0e 01 80}  //weight: 10, accuracy: High
        $x_2_4 = "http://66.148.74.7/zu2/zc.php" ascii //weight: 2
        $x_2_5 = "MESSAGE WITH ADV TEXT SENDED" ascii //weight: 2
        $x_2_6 = "Sending ADVERT TEXT to:" ascii //weight: 2
        $x_2_7 = "CONTACT TO::::>>>" ascii //weight: 2
        $x_2_8 = "?l=%s&d=%s&v=%s" ascii //weight: 2
        $x_2_9 = "rvz1=%d&rvz2=%.10u" ascii //weight: 2
        $x_2_10 = "Global\\iowerjfgiowejroigeu894389" ascii //weight: 2
        $x_2_11 = "Packet len > 100 and adv_txt >3" ascii //weight: 2
        $x_1_12 = "webmail.tiscali.co.uk/mail/MessageSend" ascii //weight: 1
        $x_1_13 = "?cmd=ComposeManage&" ascii //weight: 1
        $x_1_14 = "http://mail.rambler.ru/mail/mail.cgi?mode=compose" ascii //weight: 1
        $x_1_15 = "http://mail.google.com/mail/" ascii //weight: 1
        $x_1_16 = "/newthread.php?do=postthread" ascii //weight: 1
        $x_1_17 = "mail/MailCompose.lycos" ascii //weight: 1
        $x_1_18 = "newreply.php?do=postreply" ascii //weight: 1
        $x_1_19 = "IcqEngine" ascii //weight: 1
        $x_1_20 = "JabberEngine" ascii //weight: 1
        $x_1_21 = "UniversalWebEngine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Mespam_E_2147626466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mespam.E"
        threat_id = "2147626466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mespam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 5c 28 ff 30 1c 32 3b 44 24 20 75 02 33 c0 42 40 3b d1 72 ea}  //weight: 1, accuracy: High
        $x_1_2 = "SOCKET2.DLL" ascii //weight: 1
        $x_1_3 = {75 0f 8b 54 1e 24 89 55 c4 b9 01 00 00 00 89 4d e8 47 8b 55 c0 3b fa 7c cc eb 33}  //weight: 1, accuracy: High
        $x_1_4 = {4d 00 7a 00 4e 00 61 00 6d 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Mespam_F_2147626574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mespam.F"
        threat_id = "2147626574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mespam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 50 01 83 fa 55 0f 85 ?? ?? ?? ?? 8b 45 ?? 0f be 50 03 83 fa 3a 0f 85 ?? ?? ?? ?? 8b 75 ?? 6a 04}  //weight: 1, accuracy: Low
        $x_1_2 = {70 66 78 7a 6d 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {7a 70 75 72 73 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mespam_G_2147628510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mespam.G"
        threat_id = "2147628510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mespam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WSCWriteProviderOrder" ascii //weight: 1
        $x_1_2 = "WSCInstallProvider" ascii //weight: 1
        $x_1_3 = "newsigh.com" ascii //weight: 1
        $x_1_4 = "/newsj.php" ascii //weight: 1
        $x_1_5 = "Zaebiz.GoogleSearch.Lsp.Mutex" ascii //weight: 1
        $x_1_6 = "{\"machine_id\":\"abcdefghijkl\",\"history\":\"\"}" ascii //weight: 1
        $x_1_7 = "^(GET|POST)\\s+(.+)\\s+HTTP\\/\\d\\.\\d" ascii //weight: 1
        $x_10_8 = {74 24 81 fe a0 00 00 00 75 07 e8 ?? ?? 00 00 eb 15 81 fe 02 02 00 00 74 08 81 fe a2 00 00 00 75 05 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

