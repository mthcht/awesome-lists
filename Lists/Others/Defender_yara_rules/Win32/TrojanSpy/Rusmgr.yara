rule TrojanSpy_Win32_Rusmgr_A_2147640861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Rusmgr.A"
        threat_id = "2147640861"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Rusmgr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 74 31 fc 8d 7c 39 fc c1 f9 02 78 ?? fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc}  //weight: 1, accuracy: Low
        $x_1_2 = "P%S%V%Y%\\%" ascii //weight: 1
        $x_1_3 = "RunMsgrs" ascii //weight: 1
        $x_1_4 = "RCPT TO:<" ascii //weight: 1
        $x_1_5 = "HeloName" ascii //weight: 1
        $x_1_6 = "UseEhlo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

