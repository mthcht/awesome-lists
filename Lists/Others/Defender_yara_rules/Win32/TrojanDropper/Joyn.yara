rule TrojanDropper_Win32_Joyn_A_2147606175_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Joyn.gen!A"
        threat_id = "2147606175"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Joyn"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 80 00 00 00 6a 30 6a 30 6a 02 68 00 00 00 40 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {68 04 01 00 00 e8 ?? ?? ?? ?? 6a 01 68 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? b8 01 00 00 00 c9 c2 10 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 00 4a 00 4f 00 59 00 [0-48] 2e 00 4a 00 50 00 47 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Joyn_A_2147606175_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Joyn.gen!A"
        threat_id = "2147606175"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Joyn"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EnumResourceNamesA" ascii //weight: 1
        $x_1_2 = "LoadResource" ascii //weight: 1
        $x_1_3 = "SizeofResource" ascii //weight: 1
        $x_4_4 = {00 4f 50 45 4e 00}  //weight: 4, accuracy: High
        $x_5_5 = {4e 4a 4f 59 00}  //weight: 5, accuracy: High
        $x_10_6 = {6a 00 68 80 00 00 00 6a (02|30) 6a 00 6a 02 68 00 00 00 40 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 f8 6a 00 8d 45 fc 50 ff 75 e8 ff 75 ec ff 75 f8 e8 ?? ?? ?? ?? ff 75 f8 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 04 01 00 00 e8 ?? ?? ?? ?? 6a 01 68 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

