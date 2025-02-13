rule TrojanDownloader_Win32_Jadtre_A_2147627813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Jadtre.A"
        threat_id = "2147627813"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Jadtre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 14 8b 45 fc 8b 00 f7 d0 8b 4d fc 03 41 04 8b 4d fc 89 01 eb}  //weight: 2, accuracy: High
        $x_1_2 = {6a 04 8d 45 f4 50 68 93 21 22 00 ff 75 f8 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {c7 40 fb e9 00 00 00 8b 45 f4 03 45 f8 8b 4d fc 2b c8 8b 45 f4 03 45 f8 89 48 fc 8b 45 f4 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Jadtre_B_2147652731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Jadtre.B"
        threat_id = "2147652731"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Jadtre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ID=%s&fn=%s_%s&Var=%.8X" ascii //weight: 1
        $x_1_2 = "%sautorun.inf" ascii //weight: 1
        $x_1_3 = {68 72 72 f2 e1 ff 75 ?? ff 55 ?? 8d 45 ?? 50 ff 75 ?? ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

