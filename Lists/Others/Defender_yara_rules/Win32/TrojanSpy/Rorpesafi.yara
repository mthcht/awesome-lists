rule TrojanSpy_Win32_Rorpesafi_A_2147697452_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rorpesafi.A"
        threat_id = "2147697452"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rorpesafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {64 72 69 76 65 72 73 2e 78 33 32 00 ff ff ff ff 09 00 00 00 73 72 74 66 6c 2e 65 78 65}  //weight: 4, accuracy: High
        $x_2_2 = "saneksuper33hdinjr" ascii //weight: 2
        $x_2_3 = "wj63jdd90834502" ascii //weight: 2
        $x_2_4 = "sismforal.sys" ascii //weight: 2
        $x_2_5 = "GamForWin" ascii //weight: 2
        $x_2_6 = {73 76 63 68 6f 73 74 33 32 2e 65 78 65 00 00 00 2f 69 6e 73 74 61 6c 6c 20 2f 53 49 4c 45 4e 54}  //weight: 2, accuracy: High
        $x_1_7 = "BaiduAnTray .exe" ascii //weight: 1
        $x_1_8 = "KeyHookDLL.dll" ascii //weight: 1
        $x_1_9 = "ZapuskVVV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

