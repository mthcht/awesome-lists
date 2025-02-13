rule TrojanDropper_Win32_Danmec_A_2147656931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Danmec.A"
        threat_id = "2147656931"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Danmec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 ff d6 8d 4d ?? 51 a3 ?? ?? ?? ?? c7 45 00 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 88 5d ?? e8 ?? ?? ?? ?? 83 c4 04 50 ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {ff ff 52 ff 15 ?? ?? ?? ?? 68 88 13 00 00 ff 15 0b 00 51 ff 15 ?? ?? ?? ?? 8d 95}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

