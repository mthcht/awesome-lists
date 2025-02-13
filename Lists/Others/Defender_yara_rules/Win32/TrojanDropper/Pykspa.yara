rule TrojanDropper_Win32_Pykspa_A_2147630271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Pykspa.A"
        threat_id = "2147630271"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Pykspa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 85 d8 fd ff ff 50 0f be 85 d8 fd ff ff 99 b9 05 00 00 00 f7 f9 83 c2 06 52 8d 95 b4 fd ff ff 52 e8}  //weight: 2, accuracy: High
        $x_2_2 = {0f be 8d aa fd ff ff 85 c9 75 0b 0f be 95 8f fc ff ff 85 d2 75 0b 0f b6 85 d7 fd ff ff 85 c0 74 19 0f b6 8d d7 fd ff ff 85 c9 0f 84 ?? ?? 00 00 83 7d fc 78 0f 8e ?? ?? 00 00 c7 45 fc 00 00 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {00 2e 64 00 00 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_4 = {00 2e 65 00 00 78 [0-3] 65 00}  //weight: 2, accuracy: Low
        $x_1_5 = {00 73 6f 75 70 38 38 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 74 76 66 31 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 73 61 74 31 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

