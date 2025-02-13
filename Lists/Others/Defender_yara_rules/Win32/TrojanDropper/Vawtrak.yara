rule TrojanDropper_Win32_Vawtrak_A_2147686682_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vawtrak.A"
        threat_id = "2147686682"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vawtrak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 ff 0f 00 00 0d 00 40 00 00 89 45 ec ff 75 08 e8 ?? ?? ?? ?? 59 33 d2 b9 ff 3f 00 00 f7 f1 81 c2 00 80 00 00 89 55 f0 ff 75 08 e8 ?? ?? ?? ?? 59 89 45 f4 ff 75 08 e8 ?? ?? ?? ?? 59 89 45 f8 ff 75 08 e8 ?? ?? ?? ?? 59 89 45 fc ff 75 fc ff 75 f8 ff 75 f4 ff 75 f0 ff 75 ec ff 75 e8 ff 75 e4 ff 75 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 03 59 f7 f1 83 c2 06 89 55 f8 83 65 fc 00 eb ?? 8b 45 fc 40 89 45 fc 8b 45 fc 3b 45 f8 73 1f ff 75 08 e8 ?? ?? ?? ?? 59 33 d2 6a 1a 59 f7 f1 83 c2 61 8b 45 fc 8b 4d 10 66 89 14 41}  //weight: 1, accuracy: Low
        $x_1_3 = "regsvr32.exe \"%s\"" wide //weight: 1
        $x_1_4 = {53 3a 28 4d 4c 3b 3b 4e 57 3b 3b 3b 4c 57 29 00 44 3a 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 57 44 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

