rule PWS_Win32_Selex_A_2147600939_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Selex.A"
        threat_id = "2147600939"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Selex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "220"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {b9 a5 0e 00 00 33 c0 bf ?? ?? ?? 00 52 f3 ab 66 ab 68 97 3a 00 00 6a 01 68 ?? ?? ?? 00 aa e8 ?? ?? ?? 00 8b 15 ?? ?? ?? 00 52 e8}  //weight: 100, accuracy: Low
        $x_100_2 = {89 45 f8 89 45 fc b8 01 00 00 00 0f a2 89 45 f8 89 55 fc 8b 4d f8 8b 55 fc 33 c0 33 f6 0b c1 0b d6}  //weight: 100, accuracy: High
        $x_4_3 = "QUID=%u-%I64u-" ascii //weight: 4
        $x_4_4 = "SMTP=%s&POP3=%s&NOME=%s&ADDR=%s&USER=%s&PASS=%s" ascii //weight: 4
        $x_4_5 = "Encoding took %dms" ascii //weight: 4
        $x_4_6 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 4
        $x_4_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\User Agent\\Post Platform" ascii //weight: 4
        $x_1_8 = "POP3 User Name" ascii //weight: 1
        $x_1_9 = "POP3 Server" ascii //weight: 1
        $x_1_10 = "EHLO %s" ascii //weight: 1
        $x_1_11 = "%s\\body.txt" ascii //weight: 1
        $x_1_12 = "%s\\subject.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 4 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_100_*) and 5 of ($x_4_*))) or
            (all of ($x*))
        )
}

