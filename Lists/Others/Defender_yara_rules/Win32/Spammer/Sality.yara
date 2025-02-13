rule Spammer_Win32_Sality_A_2147625321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Sality.A"
        threat_id = "2147625321"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 f9 24 0f 85 ?? ?? 00 00 8b 55 08 03 ?? ?? ef ff ff 0f be 42 01 83 f8 72 0f 85 ?? ?? 00 00 8b 4d 08 03 ?? ?? ef ff ff 0f be 51 02 83 fa 6e 0f 85 ?? ?? 00 00 8b 45 08}  //weight: 2, accuracy: Low
        $x_2_2 = {eb ab 8b 85 5c fb ff ff 35 11 f9 ad de 89 85 5c fb ff ff 8b 8d 5c fb ff ff 51 ff 15}  //weight: 2, accuracy: High
        $x_2_3 = {8a 12 32 14 08 8b 45 08 03 45 f0 88 10 e9 5f ff ff ff 8b 4d 10 8a 55 f4 88 91 00 01 00 00 8b 45 10 8a 4d ec 88 88 01 01 00 00}  //weight: 2, accuracy: High
        $x_1_4 = "[VAR%d" ascii //weight: 1
        $x_1_5 = "SPM_ID=%d" ascii //weight: 1
        $x_1_6 = "$from_mail$" ascii //weight: 1
        $x_1_7 = "$GEN_PER_MAIL$=" ascii //weight: 1
        $x_1_8 = "%s?fuck=port&mx_=%d&smtp_=%d" ascii //weight: 1
        $x_1_9 = "&s_id=%d&ver=%d&r=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

