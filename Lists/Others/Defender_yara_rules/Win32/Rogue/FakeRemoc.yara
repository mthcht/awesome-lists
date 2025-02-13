rule Rogue_Win32_FakeRemoc_140542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {49 6e 74 65 72 6e 65 74 53 65 74 43 6f 6f 6b 69 65 41 00}  //weight: 10, accuracy: High
        $x_10_2 = {75 72 6c 6d 6f 6e 2e 64 6c 6c 00}  //weight: 10, accuracy: High
        $x_2_3 = {73 65 63 5f 6d 75 74 65 78 00}  //weight: 2, accuracy: High
        $x_2_4 = {73 63 6e 73 5f 74 69 6d 65 00}  //weight: 2, accuracy: High
        $x_1_5 = "AFFID=%s" ascii //weight: 1
        $x_1_6 = "PaymentPage_Reuse" ascii //weight: 1
        $x_1_7 = {72 65 6c 65 61 73 65 5c 53 45 43 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRemoc_140542_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Program Files\\AntiMalwareGuard" ascii //weight: 10
        $x_10_2 = "antimalwareguard.com" ascii //weight: 10
        $x_10_3 = "amg.exe" ascii //weight: 10
        $x_5_4 = "actn_order_id" ascii //weight: 5
        $x_1_5 = "malwarecrashpro.com" ascii //weight: 1
        $x_1_6 = "Antivirxp08_reg" ascii //weight: 1
        $x_1_7 = "AntiSpywareMaster" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRemoc_140542_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 73 65 63 5f 6d 75 74 65 78 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "text_btn_space" wide //weight: 1
        $x_1_3 = "reminder_mutex" ascii //weight: 1
        $x_1_4 = "img_sys_icon" wide //weight: 1
        $x_1_5 = {00 5c 53 45 43 5c 62 73 74 61 74 65 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 74 61 74 69 73 74 69 63 61 6e 00 70 63 5f 69 64 3d 25 75}  //weight: 1, accuracy: High
        $x_1_7 = {00 41 63 74 69 76 61 74 69 6f 6e 44 6c 67 00}  //weight: 1, accuracy: High
        $x_1_8 = "release\\SEC.pdb" ascii //weight: 1
        $x_1_9 = "naction=%d&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRemoc_140542_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 65 72 73 6f 6e 61 6c 53 70 79 00}  //weight: 2, accuracy: High
        $x_1_2 = {52 65 61 6c 74 69 6d 65 41 6c 65 72 74 73 00 00 5a 6f 6d 62 69 65 54 68 72 65 61 74 73}  //weight: 1, accuracy: High
        $x_1_3 = {63 6f 6f 6b 69 65 00 00 72 65 67 76 61 6c 75 65}  //weight: 1, accuracy: High
        $x_1_4 = {41 75 74 6f 52 75 6e 44 6c 67 00}  //weight: 1, accuracy: High
        $x_1_5 = {41 6c 65 72 74 44 65 73 63 72 69 70 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 69 6e 73 74 61 6e 74 73 63 61 6e 00}  //weight: 1, accuracy: High
        $x_1_7 = "CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows" ascii //weight: 1
        $x_1_8 = {72 65 76 69 76 65 64 00 6c 65 76 65 6c}  //weight: 1, accuracy: High
        $x_1_9 = "deleted_after_reboot" ascii //weight: 1
        $x_1_10 = {53 63 61 6e 52 65 70 6f 72 74 73 00 52 65 70 6f 72 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRemoc_140542_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {50 61 79 6d 65 6e 74 50 61 67 65 5f 52 65 75 73 65 5f 33 35 44 35 34 31 32 45 38 35 35 43 34 30 63 34 38 35 34 44 2d 35 42 31 35 35 36 35 43 39 35 31 42 00}  //weight: 3, accuracy: High
        $x_2_2 = "Cleaner2009\\" ascii //weight: 2
        $x_1_3 = {46 69 72 73 74 41 63 74 69 76 61 74 69 6f 6e 41 74 74 65 6d 70 74 54 69 6d 65 00}  //weight: 1, accuracy: High
        $x_2_4 = {52 67 64 55 70 64 61 74 65 72 00}  //weight: 2, accuracy: High
        $x_1_5 = "SpywareRemover2009" ascii //weight: 1
        $x_2_6 = "/adv/order/?abbr=" ascii //weight: 2
        $x_1_7 = {61 63 74 6e 5f 6f 72 64 65 72 5f 69 64 00}  //weight: 1, accuracy: High
        $x_3_8 = "ABBR=DOWNLINK=DOMAINNAME=PRODUCTNAME#OWNERNAME#EMAIL#ORDERID#PASSWORD" ascii //weight: 3
        $x_1_9 = ">Order information:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRemoc_140542_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {50 65 72 73 6f 6e 61 6c 41 6e 74 69 53 70 79 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 50 41 53 5f 53 48 55 54 44 4f 57 4e 00}  //weight: 10, accuracy: High
        $x_10_3 = {00 50 41 53 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_4 = "personalantispy.com" ascii //weight: 10
        $x_10_5 = "pasi = uninstall" ascii //weight: 10
        $x_10_6 = "Handlers\\ExplorerUPAS" ascii //weight: 10
        $x_10_7 = "upashellext.WAS" ascii //weight: 10
        $x_1_8 = "1924FA29-9740-4F6B-A683-90FB42FC1237" ascii //weight: 1
        $x_1_9 = "5CAB6A79-7710-405a-9B08-A13E908534E9" ascii //weight: 1
        $x_1_10 = "InstallCookieFormat" ascii //weight: 1
        $x_1_11 = "DefaultBNURL" ascii //weight: 1
        $x_1_12 = "ShutdownWindowMessage" ascii //weight: 1
        $x_1_13 = "AppGlobalMutexName" ascii //weight: 1
        $x_1_14 = "ShellHookName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRemoc_140542_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 6e 74 69 4d 61 6c 77 61 72 65 4d 61 73 74 65 72 ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {54 6f 74 61 6c 53 63 61 6e 43 6f 75 6e 74 [0-6] 49 6e 66 65 63 74 69 6f 6e 43 6f 75 6e 74 [0-6] 49 73 50 61 69 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRemoc_140542_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nullsoft Install System" ascii //weight: 1
        $x_1_2 = "insts.spywareremover2009plus.com/?action" ascii //weight: 1
        $x_1_3 = {53 70 79 77 61 72 65 52 65 6d 6f 76 65 72 32 30 30 39 20 69 73 20 62 65 69 6e 67 20 64 6f 77 6e 6c 6f 61 64 65 64 20 74 6f 20 50 43 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRemoc_140542_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 ff ff 00 00 0d 00 00 07 80 c3}  //weight: 1, accuracy: High
        $x_1_2 = {be 1f 00 02 00 56 57 ff 75 e0 8d 4d e8 e8 ?? ?? ?? ?? 85 c0 74 32 68 19 00 02 00}  //weight: 1, accuracy: Low
        $x_1_3 = "3A9377A6-BE7F-485D-908C-D44114691389" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRemoc_140542_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {57 41 53 43 6f 6e 74 65 78 74 4d 65 6e 75 00}  //weight: 3, accuracy: High
        $x_3_2 = {73 68 65 6c 6c 65 78 5c 43 6f 6e 74 65 78 74 4d 65 6e 75 48 61 6e 64 6c 65 72 73 5c 45 78 70 6c 6f 72 65 72 57 41 53 00}  //weight: 3, accuracy: High
        $x_2_3 = "4567AB12-EDED-4675-AF10-BA15EDDB4D7A" ascii //weight: 2
        $x_1_4 = "IsPaidProduct" ascii //weight: 1
        $x_1_5 = "DownloadProductURL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRemoc_140542_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 6e 74 69 53 70 79 77 61 72 65 4d 61 73 74 65 72 ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_10_2 = {5b 50 52 4f 44 55 43 54 5f 4e 41 4d 45 5d 00 00 5b 50 52 4f 44 55 43 54 5f 50 52 45 53 41 4c 45 5d 00 00 00 5b 57 45 42 53 49 54 45 5f 55 52 4c 5d 00 00 00 70 61 67 65 2e 68 74 6d 6c}  //weight: 10, accuracy: High
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRemoc_140542_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "65"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "antimalwareguard.com" ascii //weight: 5
        $x_5_2 = "antimalwareguardpro.com" ascii //weight: 5
        $x_5_3 = "AntiMalwareGuard2008" ascii //weight: 5
        $x_10_4 = "XP Security Center" ascii //weight: 10
        $x_10_5 = "CSIDL_COOKIES" ascii //weight: 10
        $x_10_6 = "CSIDL_APPDATA" ascii //weight: 10
        $x_10_7 = "CSIDL_ADMINTOOLS" ascii //weight: 10
        $x_10_8 = "actn_order_id" ascii //weight: 10
        $x_10_9 = "actn_password" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 3 of ($x_5_*))) or
            ((6 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRemoc_140542_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 6e 74 69 53 70 79 77 61 72 65 4d 61 73 74 65 72 ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_10_2 = {44 69 61 6c 65 72 00 00 64 69 61 6c 65 72 00 00 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 69 61 6c 33 32 2e 64 6c 6c 00 00 00 00 54 72 6f 6a 61 6e 00 00 74 72 6f 6a 61 6e 00 00 42 61 63 6b 64 6f 6f 72 00 00 00 00 62 61 63 6b 64 6f 6f 72 00 00 00 00 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 00 41 64 77 61 72 65 00 00 61 64 77 61 72 65 00 00 53 70 79 77 61 72 65 00 73 70 79 77 61 72 65 00 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 69 65 73 65 74 75 70 2e 64 6c 6c}  //weight: 10, accuracy: High
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRemoc_140542_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {25 73 3d 7b 61 7d 26 25 73 3d 7b 6c 7d 26 25 73 3d 7b 66 7d 26 25 73 3d 7b 70 7d 26 25 73 3d 7b 61 64 64 74 7d 26 00}  //weight: 3, accuracy: High
        $x_3_2 = {00 56 69 72 75 73 65 73 2e 62 64 74 00 7b 61 7d 00 7b 6c 7d 00 7b 66 7d 00 7b 70 7d 00 7b 61 64 64 74 7d 00}  //weight: 3, accuracy: High
        $x_3_3 = {00 53 74 61 74 69 73 74 69 63 61 6e 00}  //weight: 3, accuracy: High
        $x_1_4 = {00 50 63 50 63 55 70 64 61 74 65 72 00}  //weight: 1, accuracy: High
        $x_3_5 = "inderNag" ascii //weight: 3
        $x_3_6 = {00 43 56 69 72 75 73 52 6f 6c 6c 69 6e 67 44 6c 67 00}  //weight: 3, accuracy: High
        $x_3_7 = {00 56 69 72 75 73 65 73 2e 62 64 74 00 43 52 6f 6c 6c 69 6e 67 44 6c 67 00}  //weight: 3, accuracy: High
        $x_1_8 = "<item name=\"W32.Spybot.AVEN\">is a worm " ascii //weight: 1
        $x_1_9 = ". The url information shows Hardcore Pornographic pages." ascii //weight: 1
        $x_1_10 = "SymbOS.Hatihati.A\">is a Trojan horse " ascii //weight: 1
        $x_1_11 = " partially erases .wma files on the comprom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRemoc_140542_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRemoc"
        threat_id = "140542"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRemoc"
        severity = "50"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PROD_COOKIE_URL=cleaner2009pro.com" ascii //weight: 1
        $x_1_2 = "AID}\\\\data.ini\\qip\\" ascii //weight: 1
        $x_1_3 = "STAT_URL=http://ins.quickinstallpack.com/?action={ACTION_ID}&qad=cln&qld={LID}&qaf={AFFID}&cnt={CNT}&lng={LNG}&order_id={OID}&lp={LP}&addt={ADDT}&pc_id={PC_ID}&err={ERR}&abbr={ABBR}" ascii //weight: 1
        $x_1_4 = "SET_PAYPAGE_URL=http://quickinstallpack.com/quickinstall/order.php?qad=cln&qld={LID}&qaf={AFFID}&lp={LP}&addt={ADDT}&nid={NID}&err={ERR}" ascii //weight: 1
        $x_1_5 = "STAT_URL=http://ulog.cleaner2009pro.com/?action={ACTION_ID}&a={AID}&l={LID}&f={AFFID}&cnt={CNT}&lng={LNG}&order_id={OID}&lp={LP}&addt={ADDT}&pc_id={PC_ID}&err={ERR}&abbr={ABBR}" ascii //weight: 1
        $x_1_6 = "STAT_URL=http://insf.quickinstallpack.com/?action={ACTION_ID}&qad=cln&qld={LID}&qaf={AFFID}&cnt={CNT}&lng={LNG}&order_id={OID}&lp={LP}&addt={ADDT}&pc_id={PC_ID}&err={ERR}&abbr={ABBR}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

