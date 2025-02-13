rule TrojanDropper_Win32_Turla_A_2147691964_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Turla.A!dha"
        threat_id = "2147691964"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Turla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 af be ad de 39 44 24 08 75 11 39 44 24 0c 75 0b 8b 44 24 04}  //weight: 1, accuracy: High
        $x_1_2 = {8b 56 3c 8d 04 32 6a 00 bb 0b 01 00 00 66 39 58 18 8b 40 28 6a 01 03 c6 56 ff d0}  //weight: 1, accuracy: High
        $x_1_3 = "\\SystemRoot\\%s\\%s.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

