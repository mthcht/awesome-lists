rule TrojanSpy_Win32_ParalaxRat_ZZ_2147772084_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/ParalaxRat.ZZ!MTB"
        threat_id = "2147772084"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "ParalaxRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e [0-255] 43 53 44 56 65 72 73 69 6f 6e [0-255] 50 72 6f 64 75 63 74 4e 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_3 = {5b 00 43 00 74 00 72 00 6c 00 [0-255] 5b 00 41 00 6c 00 74 00 [0-255] 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 53 00 74 00 61 00 72 00 74 00 [0-255] 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 45 00 6e 00 64 00}  //weight: 1, accuracy: Low
        $x_1_4 = "DeleteFile(Wscript.ScriptFullName)" wide //weight: 1
        $x_1_5 = "CreateObject" wide //weight: 1
        $x_1_6 = ".vbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_ParalaxRat_STA_2147775985_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/ParalaxRat.STA!!ParalaxRat.STA"
        threat_id = "2147775985"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "ParalaxRat"
        severity = "Critical"
        info = "ParalaxRat: an internal category used to refer to some threats"
        info = "STA: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 34 6a 00 6a 00 6a 00 6a 13 6a 3a ff 75 0c ff 75 08 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 7d fc 89 44 8f fc 2d 04 04 04 04 49 75 f1}  //weight: 1, accuracy: High
        $x_1_3 = {8a 14 0e 88 14 0f 41 83 f9 20 [0-32] 8a 14 0e 88 14 0f 41}  //weight: 1, accuracy: Low
        $x_1_4 = {88 14 30 02 ca [0-16] 8d 64 24 0c 30 0e}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 75 fc 8a 14 0e 02 04 1f 02 c2 8a 34 06 88 34 0e 88 14 06 5e fe c1 75}  //weight: 1, accuracy: High
        $x_1_6 = {5f 3b a2 e5 [0-16] f7 de 22 5a [0-16] da 6f ad b7 [0-16] 4a cd 4a f5}  //weight: 1, accuracy: Low
        $x_1_7 = {bc fa de 5c [0-16] a5 52 ef cd [0-16] ee 14 de fc [0-16] df 73 aa bc}  //weight: 1, accuracy: Low
        $x_2_8 = {5b 00 43 00 74 00 72 00 6c 00 [0-255] 5b 00 41 00 6c 00 74 00 [0-255] 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 53 00 74 00 61 00 72 00 74 00 [0-255] 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 45 00 6e 00 64 00}  //weight: 2, accuracy: Low
        $x_2_9 = "DeleteFile(Wscript.ScriptFullName)" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

