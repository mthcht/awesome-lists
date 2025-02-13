rule TrojanDropper_Win32_Xorer_B_2147641419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Xorer.B"
        threat_id = "2147641419"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c1 2c 61 3c 19 77 ?? 80 e9 47 eb ?? 8a c1 2c 30 3c 09}  //weight: 1, accuracy: Low
        $x_1_2 = {fe c2 0f be fa 81 ff ?? ?? 00 00 75 02 32 d2 30 14 30 40 3b c1 7c e9}  //weight: 1, accuracy: Low
        $x_1_3 = {75 02 33 c0 30 04 32 42 40 3b d1 7c ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

