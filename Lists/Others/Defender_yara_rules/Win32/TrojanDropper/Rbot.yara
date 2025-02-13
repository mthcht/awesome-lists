rule TrojanDropper_Win32_Rbot_A_2147624079_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rbot.A"
        threat_id = "2147624079"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 04 01 00 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 00 10 40 00 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {72 42 6f 74 4c 6f 63 61 6c 2e 65 78 65 00 4d 5a 90 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

