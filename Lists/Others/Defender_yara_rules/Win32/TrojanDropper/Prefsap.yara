rule TrojanDropper_Win32_Prefsap_2147610769_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Prefsap"
        threat_id = "2147610769"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Prefsap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 08 83 e8 0c c7 40 04 32 72 65 73 c7 00 78 70 73 70 c7 05 ?? ?? ?? ?? 01 00 00 00 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {03 45 08 83 e8 08 8b 08 81 f9 70 61 70 69 0f 85 ?? 00 00 00 68 c4 09 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 55 10 8a 38 c0 c2 03 32 fa c0 cf 04 32 f9 88 38 40 41 3b 4d 0c 72 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

