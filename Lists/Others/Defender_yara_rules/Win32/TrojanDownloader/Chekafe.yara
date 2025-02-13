rule TrojanDownloader_Win32_Chekafe_A_2147630301_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chekafe.A"
        threat_id = "2147630301"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chekafe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 6c 6f 63 6b 63 6f 64 65 3d 25 64 26 6d 61 63 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 3f 69 64 3d 25 73 26 69 73 57 61 6e 67 42 61 72 3d 31 00}  //weight: 1, accuracy: High
        $x_1_3 = "&PcType=WangbarPc&" ascii //weight: 1
        $x_1_4 = {b2 e5 c8 eb b9 e3 b8 e6 42 48 4f b2 e5 bc fe 2c}  //weight: 1, accuracy: High
        $x_1_5 = {ba d9 ba d9 2c d5 e2 ca c7 b1 ea cd b7 c5 b6 00}  //weight: 1, accuracy: High
        $x_1_6 = {6b db 2b 69 c0 82 00 00 00 6b ff 33 03 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

