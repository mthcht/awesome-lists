rule Rogue_Win32_FakeSmav_127652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmav"
        threat_id = "127652"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmav"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6f 6d 00 00 00 00 68 74 74 70 3a 2f 2f 61 6e 74 69 73 70 79 77 61 72 65 32 30 30 38}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\Antispyware " ascii //weight: 1
        $x_1_3 = "/browser.php?aff=" ascii //weight: 1
        $x_1_4 = {57 69 6e 49 64 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74}  //weight: 1, accuracy: High
        $x_1_5 = {73 70 6f 72 64 65 72 2e 64 6c 6c 00 25 73 20 6f 76 65 72 20 5b 25 73 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSmav_127652_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmav"
        threat_id = "127652"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmav"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Smart Antivirus 2009 Alert!" ascii //weight: 1
        $x_1_2 = "Smart Antivirus 2009\\Smart Antivirus-2009.lnk" ascii //weight: 1
        $x_1_3 = "http://smart-antivirus-2009buy.com" wide //weight: 1
        $x_1_4 = "http://78.157.143.251" wide //weight: 1
        $x_1_5 = "Autorun" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSmav_127652_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmav"
        threat_id = "127652"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmav"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Your PC is infected by spyware - 25 significant threats have been located while scanning your files and registry." wide //weight: 10
        $x_10_2 = "activate the on-fly safeguards against future intrusions" wide //weight: 10
        $x_10_3 = "buy.php?aff=" wide //weight: 10
        $x_5_4 = "Antispyware 2008" wide //weight: 5
        $x_5_5 = "Smart Antivirus-2009" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSmav_127652_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmav"
        threat_id = "127652"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmav"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ab e2 f7 c3 06 00 ad 35}  //weight: 1, accuracy: Low
        $x_1_2 = {74 39 2d 00 04 00 00 2d 00 04 00 00 2d 00 08 00 00 eb e0 0d 00 8b ?? 81 ?? ?? ?? ?? ?? 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSmav_127652_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmav"
        threat_id = "127652"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmav"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 6e 74 69 73 70 79 32 30 30 38 2e 68 6b 2f 6f 72 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "AntiSpy2008.exe" ascii //weight: 1
        $x_1_3 = {41 6e 74 69 53 70 79 20 32 30 30 38 20 68 61 73 20 62 65 65 6e 20 61 63 74 69 76 61 74 65 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {31 31 31 2d 36 36 36 2d 36 36 36 2d 34 33 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakeSmav_127652_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmav"
        threat_id = "127652"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmav"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {eb 09 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 3b 45 ?? 73 ?? 8b 4d ?? 51 e8 ?? ?? ?? ?? 83 c4 04 66 89 45 ?? 0f b7 55 ?? 81 f2 ?? ?? 00 00 52 8d 4d ?? ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {50 68 01 00 00 80 ff 15 ?? ?? ?? ?? f7 d8 1b c0 83 c0 01 88 85 ?? ?? ff ff c7 45 fc ff ff ff ff 8d 8d ?? ?? ff ff ff 15 ?? ?? ?? ?? 0f b6 8d ?? ?? ff ff 85 c9 74}  //weight: 10, accuracy: Low
        $x_10_3 = {85 ed c7 44 24 20 00 00 00 00 c7 44 24 10 01 00 00 00 76 1f 56 e8 ?? ?? ?? ?? 0f b7 c0 34 ?? 83 c4 04 8b cf 50 ff 15}  //weight: 10, accuracy: Low
        $x_10_4 = {8a 08 83 c0 01 84 c9 75 f7 2b c2 8d 70 01 8d 44 24 0c 68 ?? ?? ?? ?? 50 c7 44 24 10 00 00 00 00 e8 ?? ?? ?? ?? bf 10 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Rogue_Win32_FakeSmav_127652_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmav"
        threat_id = "127652"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmav"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 66 75 6c 6c 69 6e 73 74 61 6c 6c 2e 70 68 70 3f 61 66 66 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = "http://antispyware-2008" ascii //weight: 1
        $x_1_3 = {41 6e 74 69 76 69 72 75 73 32 30 30 38 50 52 4f 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 6e 74 69 73 70 79 77 61 72 65 20 32 30 30 38 20 69 6e 73 74 61 6c 6c 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 20 00 32 00 30 00 30 00 38 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {61 00 6e 00 74 00 76 00 72 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {41 00 6e 00 74 00 76 00 72 00 73 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakeSmav_127652_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmav"
        threat_id = "127652"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmav"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 [0-16] 41 00 6e 00 74 00 69 00 73 00 70 00 79 00 77 00 61 00 72 00 65 00 20 00 32 00 30 00 30 00 38 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 [0-16] 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 [0-16] 41 00 6e 00 74 00 69 00 73 00 70 00 79 00 77 00 61 00 72 00 65 00 20 00 32 00 30 00 30 00 38 00 [0-16] 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 00 65 00 78 00 65 00 [0-16] 4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 [0-16] 41 00 6e 00 74 00 69 00 73 00 70 00 79 00 77 00 61 00 72 00 65 00 20 00 32 00 30 00 30 00 38 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 28 00 63 00 29 00 2e 00 20 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00}  //weight: 1, accuracy: Low
        $x_10_3 = "/soft/Antispyware2008.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

