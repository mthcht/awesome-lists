rule TrojanDropper_Win32_Figpuf_A_2147626149_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Figpuf.A"
        threat_id = "2147626149"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Figpuf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 ec 01 00 00 00 33 ff ff 15 ?? ?? ?? ?? 6a 1a 59 99 f7 f9 8b 4d 08 57 8d 72 61 ff 15 ?? ?? ?? ?? 47 83 ff 0a 66 89 30 7c de}  //weight: 1, accuracy: Low
        $x_1_2 = {80 39 3d 74 33 85 c0 75 04 8b c2 eb 02 03 c7 0f b6 00}  //weight: 1, accuracy: High
        $x_1_3 = ",run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

