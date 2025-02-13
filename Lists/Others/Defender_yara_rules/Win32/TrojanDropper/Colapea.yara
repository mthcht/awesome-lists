rule TrojanDropper_Win32_Colapea_A_2147624338_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Colapea.A"
        threat_id = "2147624338"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Colapea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 7d fa bc 07 72 08 66 81 7d fa 3b 08 76 07}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 06 75 19 a1 ?? ?? ?? ?? e8 ?? ?? ff ff 83 f8 1e 75 0a b8 02 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "0x2342244h in User32.dll" ascii //weight: 1
        $x_1_4 = "WE SILINEE, QUICKER," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

