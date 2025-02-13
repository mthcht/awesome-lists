rule Rogue_Win32_FakeYak_149015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeYak"
        threat_id = "149015"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeYak"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 61 73 74 5f 75 70 64 61 74 65 5f 73 69 7a 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 70 64 61 74 65 2e 65 78 65 00 00 6f 70 65 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = "YaKrevedko" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeYak_149015_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeYak"
        threat_id = "149015"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeYak"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7b 00 61 00 66 00 66 00 69 00 64 00 7d 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 00 70 00 64 00 5f 00 64 00 65 00 62 00 75 00 67 00 2e 00 65 00 78 00 65 00 00 00 6f 00 70 00 65 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "YaKrevedko" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeYak_149015_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeYak"
        threat_id = "149015"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeYak"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 50 68 69 73 68 69 6e 67 46 69 6c 74 65 72 00 45 6e 61 62 6c 65 64}  //weight: 1, accuracy: High
        $x_1_2 = {69 64 3d 25 73 26 68 61 73 68 3d 00 50 4f 53 54 [0-5] 2f [0-5] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeYak_149015_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeYak"
        threat_id = "149015"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeYak"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 22 8b 45 0c 8d 0c 06 8b 45 10 8a 14 07 30 11 50 47 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {33 c9 0f b6 81 ?? ?? ?? ?? 8b d0 c1 ea 04 8a 92 ?? ?? ?? ?? 83 e0 0f}  //weight: 1, accuracy: Low
        $x_2_3 = {ff 4c 24 18 0f 85 15 ff ff ff 38 5c 24 0f 74 10 68 e0 93 04 00 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeYak_149015_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeYak"
        threat_id = "149015"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeYak"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 10 03 55 fc 0f be 02 8b 4d 08 03 4d f8 0f be 11 33 d0 8b 45 08 03 45 f8 88 10 8b 4d fc 83 c1 01 89 4d fc 8b 55 10 52 e8}  //weight: 1, accuracy: High
        $x_1_2 = "{coid}" ascii //weight: 1
        $x_1_3 = "{affid}" ascii //weight: 1
        $x_1_4 = "/compatibilityapplied" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeYak_149015_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeYak"
        threat_id = "149015"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeYak"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/check.php?ver=2&query=%s" ascii //weight: 1
        $x_1_2 = "http://%s/live.php?backupquery=%s" ascii //weight: 1
        $x_1_3 = "SafeReplaceMode=%i" ascii //weight: 1
        $x_1_4 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 34 2e 30 3b 20 53 4c 43 43 32 29 00}  //weight: 1, accuracy: High
        $x_1_5 = "StatsServer2=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeYak_149015_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeYak"
        threat_id = "149015"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeYak"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Internal conflict alert! Internal software conflict detected!" ascii //weight: 1
        $x_1_2 = "\\\\.\\pipe\\pipe server %s-%s-" ascii //weight: 1
        $x_1_3 = "Spyware protection is disabled. Your personal data is at high risk of being stolen and misused." ascii //weight: 1
        $x_1_4 = {6d 65 73 73 61 67 65 3d [0-10] 74 69 70 3d}  //weight: 1, accuracy: Low
        $x_1_5 = {53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 65 00 6e 00 74 00 65 00 72 00 [0-32] 41 00 63 00 74 00 69 00 76 00 61 00 74 00 65 00 6e 00 6f 00 77 00 [0-32] 41 00 66 00 74 00 65 00 72 00 53 00 63 00 61 00 6e 00}  //weight: 1, accuracy: Low
        $x_2_6 = {56 69 72 74 c7 85 ?? ?? ?? ?? 75 61 6c 50 c7 85 ?? ?? ?? ?? 72 6f 74 65 66 c7 ?? ?? ?? ?? ff 63 74 88 9d ?? ?? ?? ?? ff d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeYak_149015_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeYak"
        threat_id = "149015"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeYak"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lStatusL3=Running unsicheren Zustand sind mehrere Schwachstellen" wide //weight: 1
        $x_1_2 = "Antimalware Doctor Installer" wide //weight: 1
        $x_1_3 = "Excellent choice! ;Detects and elimininates viruses" wide //weight: 1
        $x_1_4 = "{coid}" wide //weight: 1
        $x_1_5 = "{affid}" wide //weight: 1
        $x_1_6 = "Inc. sites to Internet Explorer trusted zone." ascii //weight: 1
        $x_1_7 = "sidered if a Supporter Tool log has not been subm" ascii //weight: 1
        $x_2_8 = "inst.php?do=2&a={affid}&b={locale}&c={coid}&d={event}&e={OSVer}" ascii //weight: 2
        $x_1_9 = "Software\\Antimalware Doctor Inc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

