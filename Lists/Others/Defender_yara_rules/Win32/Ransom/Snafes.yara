rule Ransom_Win32_Snafes_A_2147727198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Snafes.A"
        threat_id = "2147727198"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Snafes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "synack@scryptmail.com" ascii //weight: 1
        $x_1_2 = "synack@countermail.com" ascii //weight: 1
        $x_1_3 = "Your files are encrypted" ascii //weight: 1
        $x_1_4 = "do not panic and write on BitMessage (using site https://bitmsg.me/):" ascii //weight: 1
        $x_1_5 = "SynAck Team." ascii //weight: 1
        $x_1_6 = "SynAck FES" ascii //weight: 1
        $x_1_7 = "extort money, files restore is an optional service." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Snafes_A_2147727208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Snafes.A!rsm"
        threat_id = "2147727208"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Snafes"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {51 52 41 50 41 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 48 8d 05 ?? ?? ?? ?? 48 2d ?? ?? ?? ?? 50 48 8d 05 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? 50 48 8d 05 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? ff d0 41 59 41 58 5a 59}  //weight: 10, accuracy: Low
        $x_5_2 = {0f ae f0 48 8b 54 24 18 48 83 3a 02 [0-6] 48 c7 c0 00 00 00 00 48 c7 c1 01 00 00 00 f0 48 0f b1 0a}  //weight: 5, accuracy: Low
        $x_5_3 = {48 89 4c 24 08 48 83 ec 68 c7 44 24 24 00 00 00 00 c7 44 24 2c 00 00 00 00 c7 44 24 20 00 00 00 00 c7 44 24 28 00 00 00 00 48 c7 44 24 30 00 00 00 00 48 83 7c 24 70 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

