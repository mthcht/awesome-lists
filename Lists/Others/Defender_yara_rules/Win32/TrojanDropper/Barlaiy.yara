rule TrojanDropper_Win32_Barlaiy_A_2147717399_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Barlaiy.A!dha"
        threat_id = "2147717399"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Barlaiy"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 00 00 90 01 f7 f9 bf 00 00 20 03 2b fa}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 6a 02 00 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 8b 44 24 ?? 81 c6 00 6a 02 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

