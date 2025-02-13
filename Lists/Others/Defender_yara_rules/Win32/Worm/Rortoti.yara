rule Worm_Win32_Rortoti_A_2147689110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rortoti.A"
        threat_id = "2147689110"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rortoti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 5c cc 40 00 c7 85 44 ff ff ff 08 80 00 00 c7 85 3c ff ff ff 68 cc 40 00 c7 85 34 ff ff ff 08 80}  //weight: 1, accuracy: High
        $x_1_2 = {2b 33 71 b5 68 36 b1 b6 33 96 fe 49 95 84 74 01 68 85 f8 48 2a 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5}  //weight: 1, accuracy: High
        $x_1_3 = "\\igfxhost.exe" ascii //weight: 1
        $x_1_4 = "{AA890095FF-5876-FFFF-76TH-77897544FF1CE}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

