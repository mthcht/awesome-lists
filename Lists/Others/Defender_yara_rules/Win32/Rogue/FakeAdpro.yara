rule Rogue_Win32_FakeAdpro_124907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 45 6e 67 69 6e 65 41 50 2e 64 6c 6c 00 43 72 65 61 74 65 53 53 45 6e 67 69 6e 65 49 6e 74 65 72 66 61 63 65 00 52 65 6c 65 61 73 65 53 53 45 6e 67 69 6e 65 49 6e 74 65 72 66 61 63 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\Release\\SSEngine.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeAdpro_124907_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntivirusPro\\SSEngine\\Release" ascii //weight: 1
        $x_1_2 = "CreateSSEngineInterface" ascii //weight: 1
        $x_1_3 = "d_REGBACKUP.sbk" ascii //weight: 1
        $x_1_4 = "Engine.dat file does not exist" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeAdpro_124907_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 6f 66 74 77 61 72 65 5c 41 6e 74 69 76 69 72 75 73 50 72 6f 00}  //weight: 10, accuracy: High
        $x_1_2 = "antivirus-pro-site.com" ascii //weight: 1
        $x_1_3 = {43 72 65 61 74 65 53 53 45 6e 67 69 6e 65 49 6e 74 65 72 66 61 63 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 3a 5c 53 53 45 6e 67 69 6e 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 53 63 61 6e 52 65 73 75 6c 74 44 6c 67 00}  //weight: 1, accuracy: High
        $x_1_6 = "Repair process has been completed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeAdpro_124907_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AdwarePro\\NewEngine\\Rebrands\\AntivirusDoktor\\Bin\\release\\Antivirus Doktor 2009.pdb" ascii //weight: 1
        $x_1_2 = "Software\\AntivirusDoktorNE" ascii //weight: 1
        $x_1_3 = "CSpyScanDlg" ascii //weight: 1
        $x_1_4 = "Please select the paths for quick scan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeAdpro_124907_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 70 79 77 61 72 65 73 00 00 00 00 56 61 6c 75 65 00 00 00 53 70 79 77 61 72 65 49 44 00}  //weight: 2, accuracy: High
        $x_1_2 = {43 72 65 61 74 65 53 53 45 6e 67 69 6e 65 49 6e 74 65 72 66 61 63 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 6e 74 69 4d 61 6c 77 61 72 65 5f 50 72 6f 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 6e 67 69 6e 65 41 50 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_2_5 = {53 70 79 77 61 72 65 20 54 68 72 65 61 74 73 00 41 64 77 61 72 65 20 54 68 72 65 61 74 73 00 00 4b 65 79 6c 6f 67 67 65 72 73 00 00 54 72 61 63 6b 69 6e 67 20 43 6f 6f 6b 69 65 73 00}  //weight: 2, accuracy: High
        $x_1_6 = {41 6e 74 69 4d 61 6c 77 61 72 65 5f 50 72 6f 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_7 = "//join1.php" ascii //weight: 1
        $x_1_8 = "latestversion/123.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeAdpro_124907_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "latestversion/AntiMalwarePro.exe" ascii //weight: 1
        $x_1_2 = "CAbstractSSEngineInterface" ascii //weight: 1
        $x_1_3 = "CSpywareSignatureArrayEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeAdpro_124907_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 6e 74 69 2d 56 69 72 75 73 2d 50 72 6f 2e 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {3f 61 63 74 69 6f 6e 3d 67 65 74 5f 64 65 6d 6f 00}  //weight: 1, accuracy: High
        $x_1_3 = {3f 61 63 74 69 6f 6e 3d 67 65 74 5f 69 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 6e 74 69 2d 56 69 72 75 73 2d 50 72 6f 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 69 6e 73 74 61 6c 65 64 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakeAdpro_124907_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 67 69 6e 65 41 50 2e 64 6c 6c [0-16] 45 6e 67 69 6e 65 20 66 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 2e 20 45 72 72 6f 72 3a 25 64 f0 00 53 65 6e 64 4c 6f 67 [0-16] 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-80] 47 6c 6f 62 61 6c 5c [0-34] 53 6f 66 74 77 61 72 65 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeAdpro_124907_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 53 44 53 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 65 3a 5c 70 72 6f 6a 65 63 74 73 5c 61 64 77 61 72 65 70 72 6f 5c 63 6c 6f 73 65 6d 66 63 5c (64 65 62|72 65 6c 65 61) 5c [0-32] 2e 70 64 62 00}  //weight: 1, accuracy: Low
        $x_1_2 = {52 53 44 53 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 65 3a 5c 70 72 6f 6a 65 63 74 73 5c 61 64 77 61 72 65 70 72 6f 5c 6e 65 77 65 6e 67 69 6e 65 5c 72 65 62 72 61 6e 64 73 5c [0-32] 5c 62 69 6e 5c (64 65 62|72 65 6c 65 61) 5c [0-32] 2e 70 64 62 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Rogue_Win32_FakeAdpro_124907_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 53 45 6e 67 69 6e 65 2e 64 6c 6c 00 43 72 65 61 74 65 53 53 45 6e 67 69 6e 65 49 6e 74 65 72 66 61 63 65 00 52 65 6c 65 61 73 65 53 53 45 6e 67 69 6e 65 49 6e 74 65 72 66 61 63 65}  //weight: 10, accuracy: High
        $x_1_2 = "Spywares" ascii //weight: 1
        $x_1_3 = "SpywareID" ascii //weight: 1
        $x_1_4 = "Signatures" ascii //weight: 1
        $x_1_5 = "StartupPrograms" ascii //weight: 1
        $x_1_6 = "Engine.dat file does not exist" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeAdpro_124907_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = ":\\under construction\\elance" ascii //weight: 10
        $x_1_2 = {4b 65 79 6c 6f 67 67 65 72 73 [0-5] 41 64 77 61 72 65 20 54 68 72 65 61 74 73 [0-5] 53 70 79 77 61 72 65 20 54 68 72 65 61 74 73}  //weight: 1, accuracy: Low
        $x_1_3 = {54 72 69 61 6c 56 65 72 73 69 6f 6e 44 6c 67 2e 63 70 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 46 3a 5c 62 69 6e 5c 41 64 74 6f 6f 6c 73 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "updates have been downloaded" ascii //weight: 1
        $x_1_6 = "mehwishcv.rtf) which is a file that" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeAdpro_124907_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "engine failed to load. error" ascii //weight: 1
        $x_1_2 = "CreateSSEngineInterface" ascii //weight: 1
        $x_1_3 = "cabstractscanitemsinfo" ascii //weight: 1
        $x_1_4 = "Definition Updates are available for %s" ascii //weight: 1
        $x_1_5 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 48 00 65 00 6c 00 70 00 65 00 72 00 50 00 [0-2] 41 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_6 = "ScheduleAP.txt" ascii //weight: 1
        $x_1_7 = "Global\\MutexAP" ascii //weight: 1
        $x_1_8 = "Global\\K781LO_M" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Rogue_Win32_FakeAdpro_124907_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1005"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {41 6e 74 69 ?? 4d 61 6c 77 61 72 65 ?? 50 72 6f 00}  //weight: 1000, accuracy: Low
        $x_2_2 = {73 70 79 77 61 72 65 20 74 68 72 65 61 74 73 00 61 64 77 61 72 65 20 74 68 72 65 61 74 73 00 00 6b 65 79 6c 6f 67 67 65 72 73 00 00 74 72 61 63 6b 69 6e 67 20 63 6f 6f 6b 69 65 73 00}  //weight: 2, accuracy: High
        $x_2_3 = {43 72 65 61 74 65 53 53 45 6e 67 69 6e 65 49 6e 74 65 72 66 61 63 65 [0-16] 52 65 6c 65 61 73 65 53 53 45 6e 67 69 6e 65 49 6e 74 65 72 66 61 63 65 [0-16] 47 6c 6f 62 61 6c 5c 4d 75 74}  //weight: 2, accuracy: Low
        $x_3_4 = {50 6c 65 61 73 65 20 73 65 6c 65 63 74 20 74 68 65 20 70 61 74 68 73 20 66 6f 72 20 71 75 69 63 6b 20 73 63 61 6e [0-16] 3a 5c 2a 2e 2a}  //weight: 3, accuracy: Low
        $x_2_5 = "Definition Updates are available for %s" ascii //weight: 2
        $x_1_6 = "Software\\PrMa_An_" ascii //weight: 1
        $x_1_7 = "EngineAP.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1000_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 3 of ($x_2_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_1000_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeAdpro_124907_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 43 20 69 73 20 62 65 69 6e 67 20 73 63 61 6e 6e 65 64 2e 2e 2e 00 00 50 6c 65 61 73 65 20 73 65 6c 65 63 74 20 74 68 65 20 73 63 61 6e 20 6f 70 74 69 6f 6e 73 20 66 72 6f 6d 20 6d 61 69 6e 20 73 63 72 65 65 6e 2e 00 00 00 00 50 6c 65 61 73 65 20 73 65 6c 65 63 74 20 74 68 65 20 70 61 74 68 73 20 66 6f 72 20 71 75 69 63 6b 20 73 63 61 6e 2e 00 50 43 20 69 73 20 62 65 6e 69 6e 67 20 73 63 61 6e 6e 65 64 2e 2e 2e 00 50 6c 65 61 73 65 20 73 65 6c 65 63 74 20 74 68 65 20 70 61 74 68 73 20 66 6f 72 20 71 75 69 63 6b 20 73 63 61 6e}  //weight: 1, accuracy: High
        $x_1_2 = {53 63 61 6e 20 70 72 6f 63 65 73 73 20 68 61 73 20 62 65 65 6e 20 61 62 6f 72 74 65 64 20 62 79 20 75 73 65 72 2e 00 00 50 43 20 73 63 61 6e 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 6c 65 74 65 64 00 00 53 63 61 6e 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 6c 65 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e 00 00 00 53 68 6f 77 20 53 63 61 6e 20 4c 6f 67 00 00 00 53 63 61 6e 6e 69 6e 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeAdpro_124907_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 53 45 6e 67 69 6e 65 20 6d 6f 64 75 6c 65 20 69 73 20 66 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 2e 20 45 72 72 6f 72 3a 25 64 00}  //weight: 2, accuracy: High
        $x_1_2 = " recommend backing up your regularly " wide //weight: 1
        $x_1_3 = " version of our software will remove 0 problems " wide //weight: 1
        $x_1_4 = "Worms are unwanted pieces of codes, that add themselves to exe files" wide //weight: 1
        $x_1_5 = {20 00 63 00 75 00 73 00 74 00 6f 00 6d 00 69 00 7a 00 65 00 20 00 70 00 61 00 74 00 68 00 20 00 66 00 6f 00 72 00 20 00 73 00 63 00 61 00 6e 00 69 00 6e 00 67 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeAdpro_124907_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeAdpro"
        threat_id = "124907"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAdpro"
        severity = "86"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "frantik1/definitions" ascii //weight: 2
        $x_2_2 = {66 72 61 6e 74 69 6b 31 2f 75 70 64 61 74 65 2e 74 78 74 00}  //weight: 2, accuracy: High
        $x_2_3 = {47 6c 6f 62 65 36 39 00}  //weight: 2, accuracy: High
        $x_2_4 = {4b 65 79 6c 6f 67 67 65 72 73 00 00 41 64 77 61 72 65 20 54 68 72 65 61 74 73 00 00 53 70 79 77 61 72 65 20 54 68 72 65 61 74 73 00 25 73 00}  //weight: 2, accuracy: High
        $x_2_5 = {53 70 79 70 72 6f 55 70 64 61 74 65 72 41 67 65 6e 74 00}  //weight: 2, accuracy: High
        $x_2_6 = {53 70 79 77 61 72 65 73 00 00 00 00 56 61 6c 75 65 00 00 00 53 70 79 77 61 72 65 49 44 00}  //weight: 2, accuracy: High
        $x_2_7 = {53 70 79 77 61 72 65 73 00 00 00 00 49 44 00 00 4e 61 6d 65 00 00 00 00 44 65 74 61 69 6c 73 00}  //weight: 2, accuracy: High
        $x_2_8 = "e:\\Projects\\AdwarePro\\" ascii //weight: 2
        $x_1_9 = "Select custom path for quick scan" ascii //weight: 1
        $x_1_10 = {50 43 20 73 63 61 6e 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 6c 65 74 65 64 00}  //weight: 1, accuracy: High
        $x_1_11 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 73 74 6f 70 20 74 68 65 20 53 63 61 6e 6e 69 6e 67 20 50 72 6f 63 65 73 73 3f 00}  //weight: 1, accuracy: High
        $x_1_12 = {2f 6a 6f 69 6e 31 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_13 = "CScanScheduler" ascii //weight: 1
        $x_1_14 = {43 72 65 61 74 65 53 53 45 6e 67 69 6e 65 49 6e 74 65 72 66 61 63 65 00}  //weight: 1, accuracy: High
        $x_1_15 = "A_VPEngine.dat" ascii //weight: 1
        $x_1_16 = "CSpyClientDlg" ascii //weight: 1
        $x_1_17 = {45 00 6e 00 67 00 69 00 6e 00 65 00 41 00 50 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = {4d 75 74 65 78 52 44 46 72 00}  //weight: 1, accuracy: High
        $x_1_19 = "CSpyScanDlg" ascii //weight: 1
        $x_1_20 = "Engine failed to load. Error" ascii //weight: 1
        $x_1_21 = "CAbstractScanItemsInfo" ascii //weight: 1
        $x_1_22 = {52 44 66 72 4e 45 53 63 68 65 64 75 6c 65 72 00}  //weight: 1, accuracy: High
        $x_1_23 = {47 6c 6f 62 61 6c 5c 4d 75 74 65 78 41 4d 50 00}  //weight: 1, accuracy: High
        $x_1_24 = {47 6c 6f 62 61 6c 5c 4d 75 74 65 78 50 72 4d 61 41 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

