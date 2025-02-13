rule TrojanSpy_Win32_Linog_A_2147666409_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Linog.A"
        threat_id = "2147666409"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Linog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c8 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 a0 ?? ?? ?? ?? 88 85 c4 fa ff ff 6a 31 6a 00 8d 85 c5 fa ff ff 50 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {5c 73 79 73 63 6f 6e 66 69 67 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "/download/cdata/" ascii //weight: 1
        $x_1_4 = "local.foo.com.txt" ascii //weight: 1
        $x_1_5 = {2f 63 75 70 6c 6f 61 64 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 63 64 61 74 61 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {77 6f 72 6c 64 72 65 61 64 2e 6e 65 74 31 36 2e 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_8 = "%sHost: %s" ascii //weight: 1
        $x_1_9 = {73 73 70 6f 6f 6c 2e 76 62 73 00}  //weight: 1, accuracy: High
        $x_1_10 = {54 00 68 00 65 00 6d 00 65 00 73 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 6c 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = "system32\\net view > c:\\windows\\temp\\a1.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

