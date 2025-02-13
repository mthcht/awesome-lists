rule TrojanDropper_Win32_Brackash_A_2147602712_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Brackash.gen!A"
        threat_id = "2147602712"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Brackash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_2 = "zqdb1.dll" ascii //weight: 1
        $x_1_3 = "zqdb2.dll" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_5 = "CreateMutexA" ascii //weight: 1
        $x_1_6 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Brackash_B_2147602715_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Brackash.gen!B"
        threat_id = "2147602715"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Brackash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {75 7f 83 7b 04 00 7e 79 8d 55 fc 8b 43 04 e8 ?? ?? ff ff 8b 55 fc b8 ?? ?? ?? ?? e8 ?? ?? f8 ff 85 c0 7e 34}  //weight: 10, accuracy: Low
        $x_10_2 = {84 c0 75 3f 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? b2 01 a1 ?? ?? ?? ?? e8 ?? ?? f9 ff 8b f0 8d 45 ec b9 ?? ?? ?? ?? 8b 55 fc e8 ?? ?? f8 ff 8b 55 ec 8b c6 e8 ?? ?? f9 ff 8b c6 e8 ?? ?? f8 ff 8d 45 e8 b9 ?? ?? ?? ?? 8b 55 fc e8 ?? ?? f8 ff 8b 45 e8 e8 ?? ?? f8 ff 84 c0 75 3f}  //weight: 10, accuracy: Low
        $x_2_3 = {7a 71 64 62 (31|32) 2e 64 6c 6c 00}  //weight: 2, accuracy: Low
        $x_2_4 = {6d 79 64 6c 6c (31|32) 00}  //weight: 2, accuracy: Low
        $x_2_5 = {72 61 6e 64 6f 6d 66 75 6e 63 69 6f 6e 64 69 72 6d 65 6d 6f 72 79 (6c 69|68 61) 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

