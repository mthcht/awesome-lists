rule TrojanProxy_Win32_Pramro_B_2147608875_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Pramro.B"
        threat_id = "2147608875"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pramro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 85 d4 ef ff ff 83 f8 47 75 18 0f be 8d d5 ef ff ff 83 f9 45 75 0c 05 00 e9 ?? 04 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 84 15 f4 eb ff ff 34 ?? 8b 8d ec db ff ff 88 84 0d f4 eb ff ff eb c5}  //weight: 1, accuracy: Low
        $x_1_3 = {68 6f 73 74 61 2e 65 78 65 00 73 74 72 63 73 70 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

