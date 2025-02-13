rule TrojanSpy_Win32_Sappwort_A_2147583205_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Sappwort.A"
        threat_id = "2147583205"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sappwort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2200"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {8d 83 04 03 00 00 ba ?? ?? 45 00 e8 ?? ?? fb ff 8d 83 08 03 00 00 ba ?? ?? 45 00 e8 ?? ?? fb ff}  //weight: 1000, accuracy: Low
        $x_1000_2 = {b3 01 33 c0 55 68 ?? ?? 45 00 64 ff 30 64 89 20 8d 45 f8 50 8d 45 f4 e8 ?? ?? ?? ff 8b 45 f4 b9 03 00 00 00 ba 01 00 00 00 e8 ?? ?? ?? ff 8d 45 f8 ba ?? ?? 45 00 e8 ?? ?? ?? ff 8b 4d f8 b2 01}  //weight: 1000, accuracy: Low
        $x_1000_3 = {6a 00 6a 00 ff b3 04 03 00 00 68 ?? ?? 45 00 8d 4d f4 8b 83 00 03 00 00 8b 55 fc 8b 38 ff 57 0c ff 75 f4 8d 45 f8 ba 03 00 00 00 e8 ?? ?? ?? ff 8b 45 f8 e8 ?? ?? ?? ff 50 68 ?? ?? 45 00 68 ?? ?? 45 00 8b c3}  //weight: 1000, accuracy: Low
        $x_1000_4 = {6a 00 6a 00 8b 45 f8 e8 ?? ?? ?? ff 50 68 ?? ?? 45 00 68 ?? ?? 45 00 8b c3 e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff ff 45 fc 4e 75 aa}  //weight: 1000, accuracy: Low
        $x_100_5 = {ff ff ff ff 0a 00 00 00 5c 73 79 73 74 65 6d 33 32 5c 00}  //weight: 100, accuracy: High
        $x_100_6 = "\\system32\\audit.exe" ascii //weight: 100
        $x_100_7 = "\\system32\\winsys.exe" ascii //weight: 100
        $x_100_8 = {ff ff ff ff 04 00 00 00 55 49 4e}  //weight: 100, accuracy: High
        $x_100_9 = {ff ff ff ff 04 ff 00 00 55 49 4e}  //weight: 100, accuracy: High
        $x_100_10 = "%20%20%20Passwort%20:%20" ascii //weight: 100
        $x_100_11 = "%20%20%20Pass`ort%20:%20" ascii //weight: 100
        $x_100_12 = {25 32 30 25 32 30 25 32 30 50 61 73 73 77 6f 72 74 25 32 30 11 25 32 30}  //weight: 100, accuracy: High
        $x_100_13 = {25 32 30 25 32 30 25 32 30 50 61 73 73 77 6f 90 74 25 32 30 3a 25 32 30}  //weight: 100, accuracy: High
        $x_100_14 = "%20%20%20Passwort%:0:%20" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1000_*) and 2 of ($x_100_*))) or
            ((3 of ($x_1000_*))) or
            (all of ($x*))
        )
}

