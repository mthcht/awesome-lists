rule TrojanSpy_Win32_QQspy_A_2147658071_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/QQspy.A"
        threat_id = "2147658071"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "QQspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
        $x_1_2 = "huup://10.1.254.233/index.asp*" ascii //weight: 1
        $x_1_3 = {54 45 4e 43 45 4e 54 00}  //weight: 1, accuracy: High
        $x_1_4 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 08 88 0a c3 0f b7 08 66 89 0a c3}  //weight: 1, accuracy: High
        $x_1_6 = {4c 6f 63 61 6c 50 6f 72 74 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 36 36 35 30 30 00}  //weight: 1, accuracy: Low
        $x_1_7 = {68 74 74 70 3a 2f 2f 31 30 2e 31 2e 32 35 34 2e 32 33 33 2f 64 6f 77 6e 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

