rule TrojanDropper_Win32_Ifnapod_A_2147603494_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Ifnapod.A"
        threat_id = "2147603494"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Ifnapod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 24 00 00 ff 74 24 10 18 00 68 00 00 00 80 56 ff 15 ?? ?? ?? ?? 53 50 89 44 24 18 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 85 01 ff ff ff 4e c6 85 00 ff ff ff 57 ff 15 2f 00 6a 3a be ?? ?? ?? 00 8d bd 00 ff ff ff f3 a5 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

