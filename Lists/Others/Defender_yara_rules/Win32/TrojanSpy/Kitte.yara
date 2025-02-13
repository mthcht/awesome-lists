rule TrojanSpy_Win32_Kitte_A_2147678814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Kitte.A"
        threat_id = "2147678814"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Kitte"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 49 53 49 54 45 44 00 7c 00 00 00 3d 00 00 00 23 23 23 00 2f 00 00 00 68 74 74 70 73 00 00 00 68 74 74 70 00 00 00 00 7c 7c 30 00 23 23 00 00 77 00 00 00 5c 76 69 73 69 74 65 64 2e 64 61 74}  //weight: 1, accuracy: High
        $x_1_2 = {07 38 87 6b 54 72 61 63 6b 49 45 57 64 00 00 00 ff ff ff ff 08 38 46 62 49 54 72 61 63 6b 49 45}  //weight: 1, accuracy: High
        $x_1_3 = "TTIEBHO.TrackIE " ascii //weight: 1
        $x_1_4 = {26 6f 73 3d 00 00 00 00 26 69 65 76 65 72 3d 00 6d 61 63 3d 00 00 00 00 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

