rule TrojanDropper_Win32_Ldpinch_B_2147606818_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Ldpinch.B"
        threat_id = "2147606818"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldpinch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 81 39 4d 5a 75 0d 8b 41 3c 03 c1 81 38 50 45 00 00 74 02 33 c0}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\TEMP\\0800.tmp" ascii //weight: 1
        $x_1_3 = "WinlogonDLL.dll" ascii //weight: 1
        $x_1_4 = {13 a1 05 c2 57 c0 6b 91 57 c0 6b 91 57 c0 6b 91 d4 c8 36 91 54 c0 6b 91 57 c0 6a 91 5d c0 6b 91 52 cc 0b 91 55 c0 6b 91 52 cc 31 91 56 c0 6b 91}  //weight: 1, accuracy: High
        $x_1_5 = {ed 28 a5 99 ed 28 a5 99 ed 28 a5 99 ec 28 a5 99 6e 20 f8 99 ee 28 a5 99 ed 28 a4 99 e5 28 a5 99 e8 24 c5 99 e8 28 a5 99 e8 24 f9 99 ec 28 a5 99 e8 24 ff 99 ec 28 a5 99 52 69 63 68 ed 28 a5 99}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

