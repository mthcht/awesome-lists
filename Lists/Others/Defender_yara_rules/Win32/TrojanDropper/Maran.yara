rule TrojanDropper_Win32_Maran_AU_2147597097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Maran.AU"
        threat_id = "2147597097"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Maran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VoiceManagerDown" ascii //weight: 1
        $x_1_2 = "\\od3mdi.dll" ascii //weight: 1
        $x_1_3 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_4 = "avp.exe" ascii //weight: 1
        $x_1_5 = {64 65 6c 70 6c 6d 65 2e 62 61 74 00 ff ff ff ff 09 00 00 00 40 65 63 68 6f 20 6f 66 66 00 00 00 ff ff ff ff 05 00 00 00 3a 6c 6f 6f 70 00 00 00 ff ff ff ff 05 00 00 00 64 65 6c 20 22 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {07 00 00 00 77 69 6e 78 70 6e 70 00 ff ff ff ff 03 00 00 00 65 78 65 00 ff ff ff ff 01 00 00 00 5c 00 00 00 41 75 64 69 6f 20 41 64 61 70 74 65 72 00 00 00 56 47 41 44 6f 77 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

