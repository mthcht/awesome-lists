rule PWS_Win32_Sacanph_A_2147645927_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sacanph.A"
        threat_id = "2147645927"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sacanph"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 72 6f 67 72 61 6d 6d [0-13] 75 72 6c [0-13] 75 73 65 72 [0-13] 70 61 73 73 [0-13] 43 6f 6d 70 75 74 65 72 6e 61 6d 65}  //weight: 10, accuracy: Low
        $x_1_2 = {48 6f 73 74 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 61 73 6b 6d 61 6e 61 67 65 72 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "DisableTaskMgr\"=dword:1 >> %WINDIR%\\DXM.reg" ascii //weight: 1
        $x_1_5 = {4b 65 69 6e 65 20 50 72 6f 66 69 6c 65 20 67 65 66 75 6e 64 65 6e 20 67 65 66 75 6e 64 65 6e 21 00}  //weight: 1, accuracy: High
        $x_1_6 = {52 65 67 69 73 74 72 79 2d 4b 65 79 20 6e 6f 74 20 66 6f 75 6e 64 21 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Sacanph_B_2147648874_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sacanph.B"
        threat_id = "2147648874"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sacanph"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "action=add&a=" ascii //weight: 2
        $x_2_2 = {3c 2f 55 73 65 72 3e [0-16] 3c 50 61 73 73 3e [0-16] 3c 2f 50 61 73 73 3e [0-16] 3c 50 6f 72 74 3e [0-16] 3c 2f 50 6f 72 74 3e}  //weight: 2, accuracy: Low
        $x_2_3 = {6f 72 69 67 69 6e 5f 75 72 6c [0-16] 26 6c 3d [0-16] 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65}  //weight: 2, accuracy: Low
        $x_1_4 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_5 = "\\FileZilla\\recentservers.xml" ascii //weight: 1
        $x_1_6 = "\\Mozilla\\Firefox\\Profiles\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

