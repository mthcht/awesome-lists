rule TrojanDropper_Win32_QQplug_A_2147628599_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/QQplug.A"
        threat_id = "2147628599"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "QQplug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 6e 55 6e 4c 6f 61 64 44 72 76 00 66 6e 4b 69 6c 6c 4b 49 53 00 00 00 66 6e 43 6c 69 63 6b 4c 6f 61 64 44 72 76}  //weight: 1, accuracy: High
        $x_1_2 = {33 f6 50 68 ?? ?? 40 00 6a 69 56 e8 ?? ?? ff ff 83 c4 10 89 ?? f0}  //weight: 1, accuracy: Low
        $x_1_3 = {56 50 8d 45 fc 6a 02 50 ff 75 f8 c7 45 fc 50 45 00 00 ff d7 ff 75 f8 ff 15 ?? ?? 40 00 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

