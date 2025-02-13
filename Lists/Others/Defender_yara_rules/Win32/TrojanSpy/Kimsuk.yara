rule TrojanSpy_Win32_Kimsuk_A_2147683168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Kimsuk.A"
        threat_id = "2147683168"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Kimsuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 85 db f3 a4 7e 0e 8a 0c 10 80 f1 99 88 0c 10 40 3b c3 7c f2}  //weight: 1, accuracy: High
        $x_1_2 = {5b 52 4d 4f 55 53 45 5d 00 [0-4] 5b 4c 4d 4f 55 53 45 5d 00 [0-4] 5b 44 57 4e 5d 00 [0-4] 5b 55 50 5d 00 [0-91] 4c 54 5d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

