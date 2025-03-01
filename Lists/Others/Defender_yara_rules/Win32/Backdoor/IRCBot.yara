rule Backdoor_Win32_IRCBot_QR_2147662233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCBot.QR"
        threat_id = "2147662233"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[main]" ascii //weight: 1
        $x_1_2 = "[scan]" ascii //weight: 1
        $x_1_3 = "[ftp]" ascii //weight: 1
        $x_2_4 = "rfb 003.008" ascii //weight: 2
        $x_2_5 = "TRegCrap" ascii //weight: 2
        $x_2_6 = "&echo bye" ascii //weight: 2
        $x_2_7 = {4a 4f 49 4e 00}  //weight: 2, accuracy: High
        $x_2_8 = "ADDNEW|" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCBot_TA_2147678980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCBot.TA"
        threat_id = "2147678980"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ANSII RKit" ascii //weight: 1
        $x_1_2 = "phpMyAdmin/scripts/setup.php" ascii //weight: 1
        $x_1_3 = "%3A1%3A%7Bi%3A0%3BO%3A10%3A%22PMA_Config" ascii //weight: 1
        $x_1_4 = "biz/s.ico" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCBot_TA_2147678980_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCBot.TA"
        threat_id = "2147678980"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[ddos]:" ascii //weight: 1
        $x_1_2 = "Slowloris attack()" ascii //weight: 1
        $x_1_3 = "[SUPERSYN] Done with flood" ascii //weight: 1
        $x_1_4 = "[USB]-->[%s]" ascii //weight: 1
        $x_1_5 = "[LAN]-->[%s]" ascii //weight: 1
        $x_5_6 = {0f be 00 83 e8 4e 99 b9 1a 00 00 00 f7 f9 83 c2 61 ?? ?? ?? ?? ?? ?? 88 10}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_IRCBot_HL_2147712400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCBot.HL"
        threat_id = "2147712400"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 42 53 42 6f 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 4f 4e 47 20 3a 69 72 63 2e [0-16] 2e 6e 65 74}  //weight: 1, accuracy: Low
        $x_1_3 = " : upload ok" ascii //weight: 1
        $x_1_4 = "\\Users\\Accounts.cfg" ascii //weight: 1
        $x_1_5 = "\\webmoney\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCBot_GFM_2147842284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCBot.GFM!MTB"
        threat_id = "2147842284"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 cc 8d 4d de 89 e0 89 08 e8 ?? ?? ?? ?? 89 c1 8b 45 cc 99 f7 f9 8a 4c 15 de 8b 45 d4 88 4c 05 de 8b 45 d4 83 c0 01 89 45 d4}  //weight: 10, accuracy: Low
        $x_1_2 = "alskdjfh456gvtbe789nwmqzuxicop123" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCBot_GKH_2147850655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCBot.GKH!MTB"
        threat_id = "2147850655"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 53 74 3b 53 64 7d ?? 42 89 53 74 31 c0 8b 43 74 c1 e0 02 8b 4b 6c 01 c1 8b 01 03 43 60 57 56 51 89 fe 89 c7 8b 4b 78 f3 a6 59 5e 5f 75}  //weight: 10, accuracy: Low
        $x_1_2 = "c.iracblarkcr.det" ascii //weight: 1
        $x_1_3 = "adftSorewaic\\Msoro\\Wftdoin\\CwsreurVentiorsRun\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_IRCBot_GAB_2147898380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/IRCBot.GAB!MTB"
        threat_id = "2147898380"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 74 74 70 c7 85 ?? ?? ?? ?? 3a 2f 2f 31 c7 85 ?? ?? ?? ?? 36 37 2e 39 c7 85 ?? ?? ?? ?? 39 2e 38 38 c7 85 ?? ?? ?? ?? 2e 32 32 32}  //weight: 10, accuracy: Low
        $x_1_2 = "Shutdown password entered - botnet shutting down" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

