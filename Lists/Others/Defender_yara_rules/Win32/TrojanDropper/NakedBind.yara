rule TrojanDropper_Win32_NakedBind_2147582967_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/NakedBind"
        threat_id = "2147582967"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "NakedBind"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 64 8b 38 48 8b c8 f2 af af 8b 1f 66 33 db}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 3b 4d 5a 74 08 81 eb 00 00 01 00 eb f1 bd}  //weight: 1, accuracy: High
        $x_1_3 = {40 00 ff 55 48 83 c7 07 ff 55 48 83 c7 08 ff 55 48 bb 90 01 02 40 00 be}  //weight: 1, accuracy: High
        $x_1_4 = {51 ff 55 24 89 45 5c}  //weight: 1, accuracy: High
        $x_1_5 = {ff ff eb ea 51 ff 55 0c}  //weight: 1, accuracy: High
        $x_1_6 = {84 c0 75 f2 c3 8b 53 3c 8b 74 1a 78 8d 74 1e 18 ad 91 ad}  //weight: 1, accuracy: High
        $x_1_7 = {c1 c2 03 32 10 40 80 38 00 75 f5 8b 04 24 83 04 24 02 8b fd}  //weight: 1, accuracy: High
        $x_1_8 = {39 17 75 13 0f b7 00 c1 e0 02 03 44 24 04 03 c3 8b 00 03 c3 ab eb 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

