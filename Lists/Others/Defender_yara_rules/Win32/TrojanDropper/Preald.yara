rule TrojanDropper_Win32_Preald_A_2147623426_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Preald.A"
        threat_id = "2147623426"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Preald"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 48 8a 14 01 88 10 85 f6 75 f5}  //weight: 1, accuracy: High
        $x_1_2 = {46 8b c6 6b c0 0c 83 b8 ?? ?? ?? ?? 00 75 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Preald_B_2147627122_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Preald.B"
        threat_id = "2147627122"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Preald"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 48 8a 14 01 88 10 85 f6 75 f5}  //weight: 1, accuracy: High
        $x_1_2 = {47 8b f7 c1 e6 04 83 be ?? ?? ?? ?? 00 75 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

