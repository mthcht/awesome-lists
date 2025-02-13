rule Trojan_Win32_Vernac_A_2147749513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vernac.A!dha"
        threat_id = "2147749513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vernac"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "http://%s/upload.php?id=%d&TM=%d" ascii //weight: 3
        $x_3_2 = "http://%s/Default.php?id=%d&TM=%d" ascii //weight: 3
        $x_3_3 = "Desnation %s is small than finished!" ascii //weight: 3
        $x_2_4 = "If-None-Match: PHPID=%s" ascii //weight: 2
        $x_2_5 = "filename %s error!" ascii //weight: 2
        $x_2_6 = "Check_Associations" ascii //weight: 2
        $x_1_7 = "RunOnceHasShown" ascii //weight: 1
        $x_1_8 = "ClearBrowsingHistoryOnExit" ascii //weight: 1
        $x_1_9 = "DisableFirstRunCustomize" ascii //weight: 1
        $x_4_10 = {55 8b 6c 24 18 e8 ?? ?? ?? ?? 8a 4c 33 04 c1 f8 03 32 c8 88 0c 2e 46 3b f7 72 ea 5d}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

