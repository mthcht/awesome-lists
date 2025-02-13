rule TrojanDropper_Win32_Odrtre_A_2147598112_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Odrtre.A"
        threat_id = "2147598112"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Odrtre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 00 c0 09 c0 0f 85 90 01 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 c4 00 01 00 00 be ?? ?? 40 00 ad 83 f8 01 74 2e 83 f8 02 74 75 83 f8 03 0f 84 b7 00 00 00 83 f8 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Odrtre_B_2147598158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Odrtre.B"
        threat_id = "2147598158"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Odrtre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 00 c0 09 c0 75}  //weight: 1, accuracy: High
        $x_1_2 = {81 c4 00 01 00 00 be ?? ?? 40 00 ad 83 f8 01 0f 84 2d 01 00 00 83 f8 02 0f 84 cc 00 00 00 83 f8 03 74 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

