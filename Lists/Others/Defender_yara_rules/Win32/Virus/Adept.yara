rule Virus_Win32_Adept_A_2147621455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Adept.A"
        threat_id = "2147621455"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Adept"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 6a 00 83 ec 28 8b ec 60 55 6a 78 68 50 78 2e 61 54 e8 ?? ?? ?? ?? 58 58 5f 8d 77 34 6a 0a 59 f3 a5 61 6a 00 e8 ?? ?? ?? ?? 5d c2 28 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Adept_A_2147621459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Adept.gen!A"
        threat_id = "2147621459"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Adept"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 b8 7a d9 00}  //weight: 2, accuracy: High
        $x_1_2 = {6a 02 68 70 ff ff ff}  //weight: 1, accuracy: High
        $x_2_3 = {f7 7d 14 8b 45 10 8a 04 02 30 01 46 3b 75 0c 7c e6}  //weight: 2, accuracy: High
        $x_2_4 = "ShellBotR" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

