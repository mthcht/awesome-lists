rule TrojanDropper_Win32_Alpasog_A_2147709984_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Alpasog.A"
        threat_id = "2147709984"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Alpasog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 1c 00 33 d8 83 e3 f8 8d 2c c5 00 00 00 00 33 dd c1 e3 04 8b e8 83 e5 80 33 dd 8b e8 c1 e3 11 c1 ed 08 0b dd 03 c3 83 e9 01 75 d4}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 10 8a cb 8d 1c d5 00 00 00 00 33 da 81 e3 f8 07 00 00 c1 e3 14 c1 ea 08 0b d3}  //weight: 1, accuracy: High
        $x_1_3 = {33 d8 c1 e3 04 33 d8 8b e8 83 e3 80 c1 e5 07 33 dd c1 e3 11 c1 e8 08 0b c3}  //weight: 1, accuracy: High
        $x_1_4 = "c:\\windows\\note.ini" ascii //weight: 1
        $x_1_5 = "ud.bat" ascii //weight: 1
        $x_1_6 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

