rule BrowserModifier_Win32_Pointfree_125526_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Pointfree"
        threat_id = "125526"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Pointfree"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".pointfree.co.kr" ascii //weight: 1
        $x_1_2 = "regsvr32 /u /s " ascii //weight: 1
        $x_1_3 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-26] 50 6f 69 6e 74 6d 61 6e 69}  //weight: 1, accuracy: Low
        $x_1_4 = ".php?IL_NO=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Pointfree_125526_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Pointfree"
        threat_id = "125526"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Pointfree"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.pointfree.co.kr/app/remove.php" ascii //weight: 1
        $x_1_2 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_3 = "&m2code=%s" ascii //weight: 1
        $x_1_4 = "RecoveryExeName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Pointfree_125526_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Pointfree"
        threat_id = "125526"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Pointfree"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 74 74 70 3a 2f 2f [0-4] 2e 70 6f 69 6e 74 66 72 65 65 2e 63 6f 2e 6b 72 2f}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 50 46 55 70 64 61 74 65 2e 65 78 65 00 00}  //weight: 2, accuracy: High
        $x_2_3 = "Pointfree\\PFHelper.bak" ascii //weight: 2
        $x_1_4 = {57 65 62 73 61 6c 65 53 79 73 74 65 6d 5c 57 65 62 73 48 50 2e 62 61 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 68 6f 70 43 65 6e 74 65 72 5c 53 68 6f 70 43 65 6e 74 65 72 48 65 6c 70 65 72 2e 62 61 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = "Restart*.bat\"" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

