rule Rogue_Win64_Sirefef_156258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win64/Sirefef"
        threat_id = "156258"
        type = "Rogue"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ask?t=%u&u=%u" ascii //weight: 1
        $x_1_2 = "av_install.pdb" ascii //weight: 1
        $x_1_3 = "Serial_Access_Num" ascii //weight: 1
        $x_1_4 = "lsasrv/uninstall.html" wide //weight: 1
        $x_2_5 = {ba 55 61 6f 67 e8 ?? ?? ?? ?? 48 8d 8c 24 ?? ?? ?? ?? ba 19 00 02 00 4c 8b c0 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win64_Sirefef_156258_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win64/Sirefef"
        threat_id = "156258"
        type = "Rogue"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ask?t=%u&u=%u" ascii //weight: 1
        $x_1_2 = "av_install.pdb" ascii //weight: 1
        $x_1_3 = "Serial_Access_Num" ascii //weight: 1
        $x_1_4 = "lsasrv/uninstall.html" wide //weight: 1
        $x_2_5 = {ba 55 61 6f 67 e8 ?? ?? ?? ?? 48 8d 8c 24 ?? ?? ?? ?? ba 19 00 02 00 4c 8b c0 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

