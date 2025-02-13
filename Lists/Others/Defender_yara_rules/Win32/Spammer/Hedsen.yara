rule Spammer_Win32_Hedsen_B_2147690267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Hedsen.B"
        threat_id = "2147690267"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Hedsen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "94.23.49.77" ascii //weight: 5
        $x_1_2 = "/action.php?action=get_red" ascii //weight: 1
        $x_1_3 = "/action.php?action=get_mails" ascii //weight: 1
        $x_1_4 = "MAIL FROM:<" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Hedsen_C_2147690772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Hedsen.C"
        threat_id = "2147690772"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Hedsen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/action.php?action=get_mails" ascii //weight: 1
        $x_1_2 = "<db file> <domain> <user> <template file> <resume line number optional>" ascii //weight: 1
        $x_1_3 = "/action.php?action=get_red" ascii //weight: 1
        $x_1_4 = "sent_all=%u&sent_success=%u&active_connections=%u&queue_connections=%u" ascii //weight: 1
        $x_1_5 = "mail from:<" ascii //weight: 1
        $x_1_6 = "<$user$@$domain$>; $serverDate$" ascii //weight: 1
        $x_1_7 = "by $domain$ (Postfix)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Spammer_Win32_Hedsen_D_2147693088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Hedsen.D"
        threat_id = "2147693088"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Hedsen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 57 69 6c 73 6f 6e 00 00 00 00 00 00 00 00 00 00 43 6c 61 72 6b 00 00 00 00 00 00 00 00 00 00 00 48 65 6e 64 65 72 73 6f 6e 00 00 00 00 00 00 00 52 6f 73 73 00 00 00 00 00 00 00 00 00 00 00 00 4a 61 6d 65 73 00}  //weight: 2, accuracy: High
        $x_2_2 = {00 2f 3f 67 65 74 5f 73 65 6e 64 65 72 00 00 00 00 47 45 54 00 25 5b 5e 40 5d 40 25 73 00}  //weight: 2, accuracy: High
        $x_2_3 = {00 53 65 6e 64 20 4d 61 69 6c 00 [0-3] ?? ?? ?? ?? ?? (2e|30|2d|39) (2e|30|2d|39) [0-32] 00 [0-3] 3f 67 65 74 5f 6c 65 74 74 65 72 00}  //weight: 2, accuracy: Low
        $x_1_4 = "/action.php?action=get_mails" ascii //weight: 1
        $x_1_5 = "/action.php?action=get_red" ascii //weight: 1
        $x_1_6 = {4c 6f 67 53 75 63 5f 25 59 25 6d 25 64 25 48 25 4d 25 53 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_7 = "get_mails&Processed=%d&Resolved=%d&Connected=%d&550ERROR=%d&LettersSuccessful=%d&LettersSuccessfulTls=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Hedsen_E_2147706918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Hedsen.E"
        threat_id = "2147706918"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Hedsen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 56 b8 01 00 ff ff 8b 75 08 48 23 f0 81 f2 66 de 8a 31 f7 d0 40 40 8b c8 33 c0 41 66 8b 06 46 66 33 c2 74 05}  //weight: 2, accuracy: High
        $x_1_2 = {0f b7 4e 3b 8b c6 48 89 45 fc 48 8d 44 01 19 b9 09 01 00 00 57 41 41 66 39 08 0f 85 85 00 00 00 8b 70 60}  //weight: 1, accuracy: High
        $x_1_3 = {41 00 79 00 00 00 6a 70 ff 75 08 ff 15 ?? ?? 41 00 a3 ?? ?? 41 00 8b 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

