rule Trojan_Win32_Korlia_A_2147650346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Korlia.A"
        threat_id = "2147650346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Korlia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f2 ae f7 d1 49 8d 7c ?? ?? 8b c1 c7 05 ?? ?? ?? ?? 00 00 00 00 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "bisonal" ascii //weight: 1
        $x_1_3 = "k~sv~1O~llvqxX~l1qzk" ascii //weight: 1
        $x_1_4 = "wkko%00yjq{1|r|1pm" ascii //weight: 1
        $x_1_5 = "SvcHostDLL.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Korlia_B_2147654262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Korlia.B"
        threat_id = "2147654262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Korlia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56}  //weight: 10, accuracy: High
        $x_10_2 = "bisonal" ascii //weight: 10
        $x_10_3 = " OS:%ssp%d vm:%s proxy:%s" ascii //weight: 10
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_7 = {68 74 74 70 3a 2f 2f [0-16] 2f 6a 70 2f 6e 65 77 73 ?? 2e 61 73 70}  //weight: 1, accuracy: Low
        $x_1_8 = {68 74 74 70 3a 2f 2f [0-16] 2f 6a 70 2f 73 6f 66 74 ?? 2e 72 61 72}  //weight: 1, accuracy: Low
        $x_1_9 = "%s?id=%s" ascii //weight: 1
        $x_2_10 = "taskhost" wide //weight: 2
        $x_2_11 = "WINDOWS\\tasks\\lsass.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Korlia_C_2147679090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Korlia.C"
        threat_id = "2147679090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Korlia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f2 ae f7 d1 49 74 22 8a 82 ?? ?? ?? ?? bf 00 32 c3 83 c9 ff 88 82 00 33 c0 42 f2 ae f7 d1 49 3b d1 72 de}  //weight: 1, accuracy: Low
        $x_1_2 = {00 62 69 73 6f 6e 61 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73 5c 65 72 72 2e 69 6e 69 00 00 00 00 43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 50 2f 31 2e 31 0d 0a}  //weight: 1, accuracy: High
        $x_1_4 = {00 77 6b 6b 6f 25 30 30}  //weight: 1, accuracy: High
        $x_1_5 = {2f 61 2e 61 73 70 3f 69 64 3d 25 73 25 73 00 74 65 6d 70 73 2e 69 6e 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Korlia_D_2147679173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Korlia.D"
        threat_id = "2147679173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Korlia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f2 ae f7 d1 49 74 22 8a 8a ?? ?? ?? ?? bf 00 32 cb 33 c0 88 8a 00 83 c9 ff 42 f2 ae f7 d1 49 3b d1 72 de}  //weight: 1, accuracy: Low
        $x_1_2 = {00 62 69 73 6f 6e 61 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73 5c 65 72 72 [0-7] 00 43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 50 2f 31 2e 31 0d 0a}  //weight: 1, accuracy: Low
        $x_1_4 = {00 77 6b 6b 6f 25 30 30}  //weight: 1, accuracy: High
        $x_1_5 = {73 6f 63 6b 73 3d 00 00 67 6f 70 68 65 72 3d 00 68 74 74 70 73 3d 00 00 68 74 74 70 3d 00 00 00 66 74 70 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

