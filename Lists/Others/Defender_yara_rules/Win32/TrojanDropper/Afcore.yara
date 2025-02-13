rule TrojanDropper_Win32_Afcore_D_2147643636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Afcore.D"
        threat_id = "2147643636"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 00 00 00 80 50 50 56 56 68 00 00 df 00 57 57 56}  //weight: 1, accuracy: High
        $x_1_2 = {b8 00 00 00 80 50 50 56 56 68 00 00 df 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 00 00 00 80 50 50 56 56 68 00 00 df 00 ff ?? ?? ff ?? ?? 56 ff 15}  //weight: 1, accuracy: Low
        $x_10_4 = {83 ec 40 48 74 ?? 48 74 ?? 83 e8 0d 74 ?? 2d f1 03 00 00 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

