rule Spammer_WinNT_Tedroo_A_2147632554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:WinNT/Tedroo.A"
        threat_id = "2147632554"
        type = "Spammer"
        platform = "WinNT: WinNT"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 64 3d 25 73 26 73 6d 74 70 3d (6f 6b|25 73) 26 76 65 72 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_2 = "MAIL FROM:<%s>" ascii //weight: 1
        $x_1_3 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 53 00 61 00 66 00 65 00 42 00 6f 00 6f 00 74 00 5c 00 4d 00 69 00 6e 00 69 00 6d 00 61 00 6c 00 5c 00 [0-16] 2e 00 73 00 79 00 73 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\Device\\Tcp" wide //weight: 1
        $x_1_5 = "\\Device\\Udp" wide //weight: 1
        $x_1_6 = "@@FROM_EMAIL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_WinNT_Tedroo_A_2147632715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:WinNT/Tedroo.gen!A"
        threat_id = "2147632715"
        type = "Spammer"
        platform = "WinNT: WinNT"
        family = "Tedroo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 2c 8b 45 1c 8b 40 10 0f be 00 83 f8 34 75 0b}  //weight: 1, accuracy: High
        $x_1_2 = {83 7d f8 26 74 18 eb 40 8b 45 08 8b 40 3c 89 45 fc eb 35}  //weight: 1, accuracy: High
        $x_1_3 = {c6 40 06 68 a1 ?? ?? ?? ?? c7 40 07 ?? ?? ?? ?? a1 ?? ?? ?? ?? c6 40 0b c3}  //weight: 1, accuracy: Low
        $x_1_4 = "id=%s&smtp=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

