rule TrojanDropper_Win32_SpamThru_A_2147597256_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/SpamThru.gen!A"
        threat_id = "2147597256"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "SpamThru"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "125"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {2b cf 8d 04 c5 ?? ?? ?? 00 8b 50 04 85 d2 74 1e 8b 30 8d 3c 02 83 c0 08 3b c7 73 ed 0f b7 10 03 15 ?? ?? ?? 00 01 0c 32 03 d6 40 40 eb ea}  //weight: 20, accuracy: Low
        $x_20_2 = {8b d6 8a 02 8d 72 01 88 07 47 84 c0 74 0b 49 74 0c 8a 06 88 07 47 46 eb f1 85 c9 75 0d 80 27 00 8a 06 46 84 c0 75 f9}  //weight: 20, accuracy: High
        $x_20_3 = {8a 0e 8d 46 01 88 0a 42 84 c9 74 0b 4f 74 0c 8a 08 88 0a 42 40 eb f1 85 ff 75 0a 80 22 00 8a 08 40 84 c9 75 f9}  //weight: 20, accuracy: High
        $n_125_4 = "C:\\projects\\AniTa\\32" ascii //weight: -125
        $n_125_5 = "webex" ascii //weight: -125
        $n_125_6 = "&About Olmek..." wide //weight: -125
        $x_100_7 = "vc20xc00u" ascii //weight: 100
        $n_125_8 = "D:\\Src\\IC\\Olmek" ascii //weight: -125
        $n_125_9 = "BAMBALAM_GETINI.PHP" wide //weight: -125
        $n_125_10 = "Pickup_Moeglich_Optelem" ascii //weight: -125
        $x_1_11 = "IsBadCodePtr" ascii //weight: 1
        $x_1_12 = "ResumeThread" ascii //weight: 1
        $x_1_13 = "CreateThread" ascii //weight: 1
        $x_1_14 = "CreateMutexA" ascii //weight: 1
        $x_1_15 = "IsBadWritePtr" ascii //weight: 1
        $x_1_16 = "CreateProcessA" ascii //weight: 1
        $x_1_17 = "GetLastActivePopup" ascii //weight: 1
        $x_1_18 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_19 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_20 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_21 = "Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_SpamThru_E_2147597258_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/SpamThru.gen!E"
        threat_id = "2147597258"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "SpamThru"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 59 8d 9e ff 00 00 00 f7 f9 8d 0c bf 0f be 82 ?? ?? ?? ?? 03 c1 b9 f1 ff 00 00 8b f8 99 f7 f9 8b 4d 08 8d 8c 0e ?? ?? ?? ?? 8b c2 33 d2 89 45 f8 25 ff 00 00 00 f7 f1 0f be 8e ?? ?? ?? ?? 80 be ?? ?? ?? ?? 00 8d 82 ?? ?? ?? ?? 8a 92 ?? ?? ?? ?? 88 96 ?? ?? ?? ?? 88 08 75 26 33 c0 33 d2 8a 45 f9 f7 f3 80 ba ?? ?? ?? ?? 00 74 08 8d 42 01 99 f7 fb eb ef 88 93 ?? ?? ?? ?? 88 9a ?? ?? ?? ?? ff 45 fc 4e 81 fe 00 ff ff ff 0f 8f 69 ff ff ff 5f 5e 33 c0 5b 0f b6 88 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 40}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 8e e4 89 44 8f e4 8b 44 8e e8 89 44 8f e8 8b 44 8e ec 89 44 8f ec 8b 44 8e f0 89 44 8f f0 8b 44 8e f4 89 44 8f f4 8b 44 8e f8 89 44 8f f8 8b 44 8e fc 89 44 8f fc 8d 04 8d 00 00 00 00 03 f0 03 f8 ff 24 95}  //weight: 1, accuracy: High
        $x_1_3 = {ec cc 00 00 00 8d 45 f0 50 ff 15 ?? ?? ?? ?? 8d 45 e0 50 ff 15 ?? ?? ?? ?? 66 8b 45 ea 66 3b 05 ?? ?? ?? ?? 75 3b 66 8b 45 e8 66 3b 05 ?? ?? ?? ?? 75 2e 66 8b 45 e6 66 3b 05 ?? ?? ?? ?? 75 21 66 8b 45 e2 66 3b 05 ?? ?? ?? ?? 75 14 66 8b 45 e0 66 3b 05 ?? ?? ?? ?? 75 07 a1 ?? ?? ?? ?? eb 45 8d 85 34 ff ff ff 50 ff 15 ?? ?? ?? ?? 83 f8 ff 74 1b 83 f8 02 75 12 66 83 7d ce 00 74 0b 83 7d dc 00 74 05 6a 01 58 eb 07 33 c0 eb 03 83 c8 ff 56 57 8d 75 e0 bf ?? ?? ?? ?? a5 a5 a5 a5 5f a3 ?? ?? ?? ?? 5e 50 0f b7 45 fc 50 0f b7 45 fa 50 0f b7 45 f8 50 0f b7 45 f6 50 0f b7 45 f2 50 0f b7 45 f0 50 e8 ee 1d 00 00 8b 4d 08 83 c4 1c 85 c9 74 02 89 01 c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_SpamThru_D_2147597259_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/SpamThru.gen!D"
        threat_id = "2147597259"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "SpamThru"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wodhzb.dll" ascii //weight: 1
        $x_1_2 = "C:\\WINDOWS\\SYSTEM32\\odhzb.dll" ascii //weight: 1
        $x_1_3 = "rundll32.exe \"C:\\WINDOWS\\SYSTEM32\\odhzb.dll\",run" ascii //weight: 1
        $x_1_4 = "rundll32.exe \"%s\",run" ascii //weight: 1
        $x_1_5 = "%s\\Microsoft\\%s" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_7 = "%d_%d.dll" ascii //weight: 1
        $x_1_8 = "hs5pdllv4%d" ascii //weight: 1
        $x_1_9 = "\"C:\\WINDOWS\\SYSTEM32\\odhzb.dll\",run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

