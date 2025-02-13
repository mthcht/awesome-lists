rule Virus_Win32_Minipg_B_2147733762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Minipg.B!bit"
        threat_id = "2147733762"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Minipg"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MiniPig by [WarGame,#eof]" ascii //weight: 1
        $x_1_2 = "%c%c%c%c%c%c.exe" ascii //weight: 1
        $x_1_3 = {8b 55 e8 8b 45 f4 01 d0 8b 4d e8 8b 55 f4 01 ca 0f b6 12 83 f2 4a 88 10 83 45 f4 01}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 f0 8b 55 dc 01 c2 8b 45 f0 03 45 dc 0f b6 00 34 4a 88 02 8d 45 dc ff 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

