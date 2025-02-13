rule Rogue_Win32_Sirefef_153998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Sirefef"
        threat_id = "153998"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "setScanFileName" wide //weight: 2
        $x_1_2 = "setDetectedName" wide //weight: 1
        $x_1_3 = "setScanLocation" wide //weight: 1
        $x_1_4 = "ask?t=%u&u=%u" ascii //weight: 1
        $x_1_5 = "miniIE.pdb" ascii //weight: 1
        $x_1_6 = "av_install.pdb" ascii //weight: 1
        $x_1_7 = "Serial_Access_Num" ascii //weight: 1
        $x_1_8 = "lsasrv/uninstall.html" wide //weight: 1
        $x_2_9 = {68 63 6e 63 74 33 c0 8b cb e8 90 01 04 6a 02 89 90 01 02 85 c0 58 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Sirefef_153998_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Sirefef"
        threat_id = "153998"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "setScanFileName" wide //weight: 2
        $x_1_2 = "setDetectedName" wide //weight: 1
        $x_1_3 = "setScanLocation" wide //weight: 1
        $x_1_4 = "ask?t=%u&u=%u" ascii //weight: 1
        $x_1_5 = "miniIE.pdb" ascii //weight: 1
        $x_1_6 = "av_install.pdb" ascii //weight: 1
        $x_1_7 = "Serial_Access_Num" ascii //weight: 1
        $x_1_8 = "lsasrv/uninstall.html" wide //weight: 1
        $x_2_9 = {68 63 6e 63 74 33 c0 8b cb e8 90 01 04 6a 02 89 90 01 02 85 c0 58 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

