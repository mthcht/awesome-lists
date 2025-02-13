rule TrojanClicker_Win32_RuPass_B_2147605465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/RuPass.B"
        threat_id = "2147605465"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "RuPass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "277"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "matekage.ifrance.com" ascii //weight: 1
        $x_1_2 = "meciwame.ifrance.com" ascii //weight: 1
        $x_1_3 = "pecipixi.iespana.es" ascii //weight: 1
        $x_1_4 = "trojaner-board.de" ascii //weight: 1
        $x_1_5 = "forum.kaspersky.com" ascii //weight: 1
        $x_1_6 = "castlecops.com" ascii //weight: 1
        $x_1_7 = "namepros.com" ascii //weight: 1
        $x_1_8 = "askdamage.com" ascii //weight: 1
        $x_1_9 = "webmasterworld.com" ascii //weight: 1
        $x_1_10 = "searchengineforums.com" ascii //weight: 1
        $x_1_11 = "nastraforum.com" ascii //weight: 1
        $x_1_12 = "adultwebmasterinfo.com" ascii //weight: 1
        $x_1_13 = "board.gofuckyourself.com" ascii //weight: 1
        $x_1_14 = "umaxforum.com" ascii //weight: 1
        $x_5_15 = "cs_config_sh" ascii //weight: 5
        $x_10_16 = "GetProcessWindowStation" ascii //weight: 10
        $x_10_17 = "{EF62EF34-7E5A-46ac-9383-1949547AF5D6}" ascii //weight: 10
        $x_10_18 = ".\\md5.cpp" wide //weight: 10
        $x_10_19 = "CS_Resp2" wide //weight: 10
        $x_10_20 = "Resp1" wide //weight: 10
        $x_10_21 = "Request" wide //weight: 10
        $x_10_22 = "CS_Mutex" wide //weight: 10
        $x_100_23 = "ConnectionServices" ascii //weight: 100
        $x_100_24 = "{6D7B211A-88EA-490c-BAB9-3600D8D7C503}" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 6 of ($x_10_*) and 1 of ($x_5_*) and 12 of ($x_1_*))) or
            ((2 of ($x_100_*) and 7 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_100_*) and 7 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_RuPass_18128_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/RuPass"
        threat_id = "18128"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "RuPass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {52 75 50 61 73 73 2e 52 75 50 61 73 73 5c 43 75 72 56 65 72 00 00 00 00 52 75 50 61 73 73 2e 52 75 50 61 73 73}  //weight: 10, accuracy: High
        $x_10_2 = "954A0637-9147-4b5e-964E-9F20E58FC29D" ascii //weight: 10
        $x_5_3 = {49 45 50 6c 75 67 69 6e 2e 44 4c 4c 00 52 75 6e 49 45}  //weight: 5, accuracy: High
        $x_5_4 = "EAE44826-77F9-4fb0-B4DE-1552E2626B73" ascii //weight: 5
        $x_5_5 = "12923412-C64A-48cf-A4A0-6781245DC952" ascii //weight: 5
        $x_5_6 = "E0AA8E2B-37AE-42f5-A947-5C147CA59338" ascii //weight: 5
        $x_1_7 = "ConfigMemoryMapping" ascii //weight: 1
        $x_1_8 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_RuPass_18128_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/RuPass"
        threat_id = "18128"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "RuPass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "my.begun.ru" ascii //weight: 1
        $x_1_2 = "promoforum.ru" ascii //weight: 1
        $x_1_3 = "seochase.com" ascii //weight: 1
        $x_1_4 = "mastertalk.ru" ascii //weight: 1
        $x_1_5 = "searchengines.ru" ascii //weight: 1
        $x_1_6 = "armadaboard.com" ascii //weight: 1
        $x_1_7 = "umaxforum.com" ascii //weight: 1
        $x_1_8 = "umaxlogin.com" ascii //weight: 1
        $x_1_9 = "rusawm.com" ascii //weight: 1
        $x_1_10 = "gofuckyourself.com" ascii //weight: 1
        $x_1_11 = "InstanceRunControlMutex" ascii //weight: 1
        $x_4_12 = "ConnectionServices" ascii //weight: 4
        $x_4_13 = "EF62EF34-7E5A-46ac-9383-1949547AF5D6" ascii //weight: 4
        $x_4_14 = "6D7B211A-88EA-490c-BAB9-3600D8D7C503" ascii //weight: 4
        $x_4_15 = "Release\\RuPass.pdb" ascii //weight: 4
        $x_5_16 = "rupass.com/about" ascii //weight: 5
        $x_6_17 = {00 52 75 50 61 73 73 20 25 73 00}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 8 of ($x_1_*))) or
            ((3 of ($x_4_*) and 4 of ($x_1_*))) or
            ((4 of ($x_4_*))) or
            ((1 of ($x_5_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*))) or
            ((1 of ($x_6_*) and 10 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_4_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_RuPass_18128_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/RuPass"
        threat_id = "18128"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "RuPass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "my.begun.ru" ascii //weight: 1
        $x_1_2 = "google.com/adsense/" ascii //weight: 1
        $x_1_3 = "promoforum.ru" ascii //weight: 1
        $x_1_4 = "seochase.com" ascii //weight: 1
        $x_1_5 = "mastertalk.ru" ascii //weight: 1
        $x_1_6 = "searchengines.ru" ascii //weight: 1
        $x_1_7 = "armadaboard.com" ascii //weight: 1
        $x_1_8 = "umaxforum.com" ascii //weight: 1
        $x_1_9 = "umaxlogin.com" ascii //weight: 1
        $x_1_10 = "rusawm.com" ascii //weight: 1
        $x_1_11 = "gofuckyourself.com" ascii //weight: 1
        $x_10_12 = "ConnectionServices.ConnectionServices.1\\CLSID" ascii //weight: 10
        $x_10_13 = "TypeLib\\{EF62EF34-7E5A-46ac-9383-1949547AF5D6}\\1.0\\0\\win32" ascii //weight: 10
        $x_10_14 = "Browser Helper Objects\\{6D7B211A-88EA-490c-BAB9-3600D8D7C503}" ascii //weight: 10
        $x_10_15 = "ConnectionServices module" ascii //weight: 10
        $x_10_16 = "Release\\RuPass.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 10 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

