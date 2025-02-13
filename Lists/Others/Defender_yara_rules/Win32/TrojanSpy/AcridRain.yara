rule TrojanSpy_Win32_AcridRain_A_2147730458_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AcridRain.A!bit"
        threat_id = "2147730458"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AcridRain"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 30 94 0c ?? ?? 00 00 41 3b cf 73 09 8a 94 24 ?? ?? 00 00 eb eb}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f9 0c 73 1d 32 94 0d ?? ff ff ff 88 94 0d ?? ff ff ff 41 89 8d ?? ff ff ff 8a 95 ?? ff ff ff eb de}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c1 33 d2 6a 0a 59 f7 f1 4f 8b c8 80 c2 30 88 17 85 c9 75 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

