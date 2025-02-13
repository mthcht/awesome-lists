rule PWS_Win32_Ldpinch_2147806447_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch"
        threat_id = "2147806447"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 75 62 6a 65 63 74 3a 20 50 61 73 73 [0-5] 20 66 72 6f 6d}  //weight: 2, accuracy: Low
        $x_2_2 = {26 62 3d 50 61 73 73 65 73 20 66 72 6f 6d 20 ?? 69 6e 63 68}  //weight: 2, accuracy: Low
        $x_1_3 = "\\andrq.ini" ascii //weight: 1
        $x_1_4 = "Software\\Far\\Plugin\\FTP\\Hosts" ascii //weight: 1
        $x_1_5 = "PStoreCreateInstance" ascii //weight: 1
        $x_1_6 = "LookupAccountNameA" ascii //weight: 1
        $x_1_7 = "RasEnumEntriesA" ascii //weight: 1
        $x_1_8 = "\\Wcx_ftp.ini" ascii //weight: 1
        $x_1_9 = "POP3 Password2" ascii //weight: 1
        $x_1_10 = "Software\\Ghisler\\Total Commander" ascii //weight: 1
        $x_1_11 = "SOFTWARE\\RIT\\The Bat!" ascii //weight: 1
        $x_1_12 = "SOFTWARE\\Mirabilis\\ICQ\\DefaultPrefs" ascii //weight: 1
        $x_1_13 = "crypted-password" ascii //weight: 1
        $x_1_14 = "nections\\pbk\\rasphone.pbk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Ldpinch_DE_2147806620_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.DE"
        threat_id = "2147806620"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "%s\\%s%i\\encPwd.jsd" wide //weight: 1
        $x_1_3 = "Software\\%s\\%s-Qt" wide //weight: 1
        $x_1_4 = "%s\\mbhd.wallet.aes" wide //weight: 1
        $x_1_5 = "%s\\Softwarenetz\\Mailing\\Daten\\mailing.vdt" wide //weight: 1
        $x_1_6 = "%s\\QupZilla\\profiles\\default\\browsedata.db" wide //weight: 1
        $x_1_7 = "Software\\Ciphrex\\CoinVault/Bitcoin\\recents" wide //weight: 1
        $x_10_8 = {83 c4 0c 57 57 68 9d 61 8a fa 57 e8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Ldpinch_CX_2147806766_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.CX"
        threat_id = "2147806766"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".-he-o-ru.c-o-m" ascii //weight: 10
        $x_1_2 = "*163*.txt" ascii //weight: 1
        $x_1_3 = "*alimama*.txt" ascii //weight: 1
        $x_1_4 = "*aliunion*.txt" ascii //weight: 1
        $x_1_5 = "*baidu*.txt" ascii //weight: 1
        $x_1_6 = "*google*.txt" ascii //weight: 1
        $x_1_7 = "*sina*.txt" ascii //weight: 1
        $x_1_8 = "*sogou*.txt" ascii //weight: 1
        $x_1_9 = "*sohu*.txt" ascii //weight: 1
        $x_1_10 = "*yahoo*.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Ldpinch_2147806773_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch"
        threat_id = "2147806773"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 75 62 6a 65 63 74 3a 20 50 61 73 73 [0-5] 20 66 72 6f 6d}  //weight: 2, accuracy: Low
        $x_2_2 = {26 62 3d 50 61 73 73 65 73 20 66 72 6f 6d 20 ?? 69 6e 63 68}  //weight: 2, accuracy: Low
        $x_1_3 = "\\andrq.ini" ascii //weight: 1
        $x_1_4 = {53 6f 66 74 77 61 72 65 5c 46 61 72 5c 50 6c 75 67 69 6e [0-1] 5c 46 54 50 5c 48 6f 73 74 73}  //weight: 1, accuracy: Low
        $x_1_5 = "PStoreCreateInstance" ascii //weight: 1
        $x_1_6 = "LookupAccountNameA" ascii //weight: 1
        $x_1_7 = "RasEnumEntriesA" ascii //weight: 1
        $x_1_8 = "\\Wcx_ftp.ini" ascii //weight: 1
        $x_1_9 = "POP3 Password2" ascii //weight: 1
        $x_1_10 = "Software\\Ghisler\\Total Commander" ascii //weight: 1
        $x_1_11 = "SOFTWARE\\RIT\\The Bat!" ascii //weight: 1
        $x_1_12 = "SOFTWARE\\Mirabilis\\ICQ\\DefaultPrefs" ascii //weight: 1
        $x_1_13 = "crypted-password" ascii //weight: 1
        $x_1_14 = "nections\\pbk\\rasphone.pbk" ascii //weight: 1
        $x_1_15 = "Software\\RimArts\\B2\\Settings" ascii //weight: 1
        $x_1_16 = "\\GlobalSCAPE\\CuteFTP" ascii //weight: 1
        $x_1_17 = "Software\\Mail.Ru\\Agent\\mra_logins" ascii //weight: 1
        $x_1_18 = "SOFTWARE\\FlashFXP\\3" ascii //weight: 1
        $x_1_19 = "\\ws_ftp.ini" ascii //weight: 1
        $n_1_20 = "http://spotauditor.nsauditor.com" ascii //weight: -1
        $n_100_21 = "Change Forgotten Password http://www.change-forgotten-password.com" ascii //weight: -100
        $n_100_22 = "http://www.top-password.com/password-recovery-bundle.html" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Ldpinch_C_2147806850_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.gen!C"
        threat_id = "2147806850"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Reports from pinch" ascii //weight: 3
        $x_1_2 = {49 73 4e 65 74 77 6f 72 6b 41 6c 69 76 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "Outpost Firewall Pro" ascii //weight: 1
        $x_1_4 = "attrib -r -a -h -s %1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Ldpinch_B_2147806854_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.gen!B"
        threat_id = "2147806854"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {68 6f 74 6d 61 69 6c 2e 63 6f 6d 00 73 65 6e 64 6d 61 69 6c 00}  //weight: 3, accuracy: High
        $x_1_2 = "accounts=%" ascii //weight: 1
        $x_1_3 = "</mbody>" ascii //weight: 1
        $x_1_4 = "</addrs>" ascii //weight: 1
        $x_1_5 = "</tasks>" ascii //weight: 1
        $x_1_6 = "%%fromoutlk" ascii //weight: 1
        $x_1_7 = "%%sndrdomain" ascii //weight: 1
        $x_1_8 = "%%selfdomain" ascii //weight: 1
        $x_1_9 = "%%rndname" ascii //weight: 1
        $x_1_10 = "%%rndword" ascii //weight: 1
        $x_1_11 = "%%rndmix" ascii //weight: 1
        $x_1_12 = "%d.%d.%d.%d.in-addr." ascii //weight: 1
        $x_1_13 = "wabimporter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Ldpinch_ZF_2147806855_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.ZF"
        threat_id = "2147806855"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 00 68 00 00 00 80 68 d1 17 40 00 e8 9e 02 00 00 a3 cd 17 40 00 86 d6 90 86 f2 8b 15 b4 17 40 00 81 c2 05 01 00 00 86 d6 90 86 f2 f7 da 6a 02 6a 00 52 ff 35 cd 17 40 00 e8 8f 02 00 00 6a 00 68 b8 17 40 00 68 00 01 00 00 68 d1 18 40 00 ff 35 cd 17 40 00 e8 6d 02 00 00 86 d6 90 86 f2 6a 00 68 b8 17 40 00 6a 04 68 c0 17 40 00 ff 35 cd 17 40 00 e8 4f 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 3d c0 17 40 00 ff 0f 84 0b 02 00 00 8b 1d c0 17 40 00 01 1d b4 17 40 00 81 05 b4 17 40 00 05 01 00 00 f7 1d b4 17 40 00 6a 02 6a 00 ff 35 b4 17 40 00 ff 35 cd 17 40 00 e8 17 02 00 00 f7 1d b4 17 40 00 86 d6 90 86 f2 68 b0 14 40 00 68 00 02 00 00 e8 f1 01 00 00 8d 05 d1 18 40 00 40 50 68 b0 14 40 00 e8 f7 01 00 00 6a 00 6a 20 6a 02 6a 00 6a 00 68 00 00 00 40 68 b0 14 40 00 e8 b4 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {eb 3c 6a 00 68 b8 17 40 00 ff 35 c0 17 40 00 68 d1 19 40 00 ff 35 cd 17 40 00 e8 7a 00 00 00 6a 00 68 bc 17 40 00 ff 35 c0 17 40 00 68 d1 19 40 00 ff 35 b0 17 40 00 e8 69 00 00 00 eb 00 ff 35 b0 17 40 00 e8 32 00 00 00 6a 01 6a 00 6a 00 68 b0 14 40 00 6a 00 6a 00 e8 54 00 00 00 e9 8b fd ff ff ff 35 cd 17 40 00 e8 0e 00 00 00 c3 e8 02 fd ff ff 6a 00 e8 0d 00 00 00 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Ldpinch_CB_2147806857_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.CB"
        threat_id = "2147806857"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 65 6c 6c 6f 2e 65 78 65 00 03 00 00 00 9a 9a 9a 31 32 33 2e 74 78 74 00 1d 16 00}  //weight: 1, accuracy: High
        $x_1_2 = {46 54 65 e7 65 76 53 73 37 65 87 65 87 68 78 35 67 65 76 53 73 57 53 75 67 35 73 76 57 35 67 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Ldpinch_UQ_2147806858_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.UQ"
        threat_id = "2147806858"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "417"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {33 c0 eb 1a 80 3d ?? ?? 40 00 32 74 0c 81 3d ?? ?? 40 00 33 35 34 20 75 e7 40 47 c6 07 00}  //weight: 100, accuracy: Low
        $x_100_2 = "XinchUser" ascii //weight: 100
        $x_100_3 = "EHLO localhost" ascii //weight: 100
        $x_100_4 = "220 FTP" ascii //weight: 100
        $x_1_5 = "image/jpeg" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\ShellNoRoam\\MUICache" ascii //weight: 1
        $x_1_7 = "p)R#kernel32.dll" ascii //weight: 1
        $x_1_8 = "Builder.exe" ascii //weight: 1
        $x_1_9 = "http://stasmaster.hut2.ru/rcv.php" ascii //weight: 1
        $x_1_10 = "#channel" ascii //weight: 1
        $x_1_11 = "C:\\WINDOWS\\screen.log" ascii //weight: 1
        $x_1_12 = "xinchpass" ascii //weight: 1
        $x_1_13 = "\\temp.jpg" ascii //weight: 1
        $x_1_14 = "Subject: Hello from %s" ascii //weight: 1
        $x_1_15 = "Content-Type: application/octet-stream; name=report.bin" ascii //weight: 1
        $x_1_16 = "Content-Disposition: attachment; filename=report.bin" ascii //weight: 1
        $x_1_17 = "RCPT TO: victor@rusal.ru" ascii //weight: 1
        $x_1_18 = "\\svchost.dll" ascii //weight: 1
        $x_1_19 = "\\svchost.exe" ascii //weight: 1
        $x_1_20 = "\\Generic Host Process for Win32 Services" ascii //weight: 1
        $x_1_21 = "http://localhost/st.php" ascii //weight: 1
        $x_1_22 = "Search Page" ascii //weight: 1
        $x_1_23 = "http://yandex.ru" ascii //weight: 1
        $x_1_24 = "C:\\khkhnkuh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 17 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Ldpinch_AF_2147806859_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.AF"
        threat_id = "2147806859"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MAIL FROM: werty@usa.net" ascii //weight: 1
        $x_1_2 = "Subject:for you" ascii //weight: 1
        $x_1_3 = "http://ww.fbi.gov/worldwidedlogs/addtobase.asp" ascii //weight: 1
        $x_1_4 = "http://www.fbi.gov/index.htm" ascii //weight: 1
        $x_1_5 = "wininetcachecredentials" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 1
        $x_1_7 = "POP3 Password2" ascii //weight: 1
        $x_1_8 = "POP3 Server" ascii //weight: 1
        $x_1_9 = "POP3 User Name" ascii //weight: 1
        $x_1_10 = "IMAP Password2" ascii //weight: 1
        $x_1_11 = "IMAP Server" ascii //weight: 1
        $x_1_12 = "IMAP User Name" ascii //weight: 1
        $x_1_13 = "inetcomm server passwords" ascii //weight: 1
        $x_1_14 = {0b c0 75 7c 8d b5 ?? ?? ff ff 81 3e 68 74 74 70 75 6e 8d 85 ?? ?? ff ff 50 e8 ?? ?? 00 00 81 7c 30 fc 44 61 74 61 75 58 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Ldpinch_BK_2147806860_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.BK"
        threat_id = "2147806860"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {75 bb 33 f6 56 68 80 00 00 00 6a 02 56 56 68 00 00 00 40 57 c7 80 ?? ?? ?? ?? 2e 6e 6c 73}  //weight: 3, accuracy: Low
        $x_1_2 = {05 20 07 00 00 50 6a 00 ff 75 08}  //weight: 1, accuracy: High
        $x_1_3 = {2a 2a 52 65 74 43 6f 64 65 3a 20 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 74 74 70 73 65 6e 64 2e 64 6c 6c 00 49 45 43 6c 65 61 6e 55 70 00 49 45 49 6e 69 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Ldpinch_AH_2147806862_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.AH"
        threat_id = "2147806862"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Windows NT\\CurrentVersion\\Winlogon\\Notify" ascii //weight: 10
        $x_10_2 = "StarterToCsrssThread" ascii //weight: 10
        $x_10_3 = "c.mx.mail.yahoo.com" ascii //weight: 10
        $x_10_4 = "AddFtpAccounts" ascii //weight: 10
        $x_1_5 = "CNet::AddBotInfo" ascii //weight: 1
        $x_1_6 = "CDllProtector::ProtectDLL" ascii //weight: 1
        $x_1_7 = "CMySyncSocket::ConnectTo" ascii //weight: 1
        $x_1_8 = "CFTPPwd::~CFTPPwd" ascii //weight: 1
        $x_1_9 = "CFTPPwd::GetSmartFTP" ascii //weight: 1
        $x_1_10 = "CFTPPwd::GetFileZilla" ascii //weight: 1
        $x_1_11 = "CFTPPwd::GetTotalCommander" ascii //weight: 1
        $x_1_12 = "CAuthonticateHooker::Handler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Ldpinch_CQ_2147806863_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.CQ"
        threat_id = "2147806863"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 03 f4 00 00 00 33 c0 89 43 04}  //weight: 10, accuracy: High
        $x_1_2 = "gJn_34287568_T7DD" ascii //weight: 1
        $x_1_3 = "atuando.php" ascii //weight: 1
        $x_1_4 = "C:\\systeam\\javaupdate" ascii //weight: 1
        $x_1_5 = ".to//cdmod.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Ldpinch_AV_2147806867_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.AV"
        threat_id = "2147806867"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 99 2b c2 d1 f8 50 ff d7 46 81 fe ff ff 00 00 7c ed}  //weight: 1, accuracy: High
        $x_1_2 = {8b 74 07 09 03 75 f4 33 c9 39 4c 07 51 76 24 8a 50 08 02 55 ff 8a 04 31 f6 d0 32 d0 8a c1 ?? ?? f6 eb f6 d2 32 d0 88 14 31 8b 45 f8 41 3b 4c 07 51 72 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Ldpinch_IE_2147806868_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.IE"
        threat_id = "2147806868"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "142"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {0d 0a 56 69 63 74 69 6d 20 69 73 20 4f 6e 6c 69 6e 65 2e 0d 0a}  //weight: 100, accuracy: High
        $x_10_2 = "project1.exe" ascii //weight: 10
        $x_10_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_4 = "Microsoft Corporation" ascii //weight: 10
        $x_10_5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 10
        $x_1_6 = "192.168.0." ascii //weight: 1
        $x_1_7 = "151.164.1.8" ascii //weight: 1
        $x_1_8 = "212.101.97.7" ascii //weight: 1
        $x_1_9 = "151.164.23.201" ascii //weight: 1
        $x_1_10 = "ege.edu.tr" ascii //weight: 1
        $x_1_11 = "www.bigglook.com" ascii //weight: 1
        $x_1_12 = "systemdna@Yahoo.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Ldpinch_BR_2147806869_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.BR"
        threat_id = "2147806869"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 00 00 40 00 8b 45 24 66 33 c0 66 81 38 4d 5a 74 07 2d 00 00 01 00 eb}  //weight: 1, accuracy: High
        $x_1_2 = {64 8b 40 30 0f b6 40 02 85 c0 75 ?? e8 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 64 8b 40 18 8b 40 30 c7 40 08 00 00 40 00}  //weight: 1, accuracy: High
        $x_1_4 = {0f 31 8b d8 68 f4 01 00 00 e8 ?? ?? ?? 00 0f 31 2b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Ldpinch_ZH_2147806874_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.ZH"
        threat_id = "2147806874"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aq.qq.com/cn2/findpsw" ascii //weight: 1
        $x_1_2 = "c:\\windows\\system32\\ip.txt" ascii //weight: 1
        $x_1_3 = "QQ.exe" ascii //weight: 1
        $x_1_4 = "365206988@qq.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Ldpinch_ZT_2147806875_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Ldpinch.ZT"
        threat_id = "2147806875"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aq.qq.com/cn2/findpsw" ascii //weight: 1
        $x_1_2 = "QQ.exe" ascii //weight: 1
        $x_1_3 = "The Bat!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

