rule Backdoor_Win32_Smadow_A_2147645576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Smadow.gen!A"
        threat_id = "2147645576"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Smadow"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 65 6e 64 74 ?? 81 7d 0c 72 65 63 76 74 ?? cc eb ?? 83 7d ?? 00 75}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 64 69 73 63 0f 84 ?? ?? 00 00 3d 73 65 6e 64 0f 84 ?? ?? 00 00 3d 63 6e 63 74 74 ?? 3d 72 65 63 76 74 ?? cc e9}  //weight: 2, accuracy: Low
        $x_1_3 = "AD Network" wide //weight: 1
        $x_1_4 = "\\systemroot\\tmp\\bot.log" wide //weight: 1
        $x_1_5 = "\\??\\%s\\{217F200B-97B8-468d-AC3B-8577E112EEC1}.tlb" wide //weight: 1
        $x_1_6 = "%u:config_missing_or_corrupt" ascii //weight: 1
        $x_1_7 = "User-Agent: Microsoft-CryptoAPI/%u.%u" ascii //weight: 1
        $x_1_8 = "my key is %S, my version is %u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Smadow_B_2147646431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Smadow.gen!B"
        threat_id = "2147646431"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Smadow"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 5d 04 00 00 eb ?? 53 68 73 65 6e 64 8b c7 8b ce e8 ?? ?? ff ff 8b d8 85 db 75 ?? ff 76 78 e8 ?? ?? 00 00 6a 08 58 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 64 69 73 63 0f 84 ?? ?? 00 00 3d 73 65 6e 64 0f 84 ?? ?? 00 00 3d 63 6e 63 74 74 ?? 3d 72 65 63 76 74 ?? cc e9}  //weight: 2, accuracy: Low
        $x_1_3 = {c7 00 2e 63 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = "GET /dll/%u.dll HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

