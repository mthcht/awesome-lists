rule TrojanDropper_Win32_Ambler_E_2147650189_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Ambler.E"
        threat_id = "2147650189"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Ambler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 50 68 f5 01 00 00 6a 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 0f 84 ?? ?? ?? ?? 56 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {88 06 0f be 43 01 0f be 4c 2f 01 50 51 e8 ?? ?? ?? ?? 88 46 01 0f be 53 02 0f be 44 2f 02 52 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

