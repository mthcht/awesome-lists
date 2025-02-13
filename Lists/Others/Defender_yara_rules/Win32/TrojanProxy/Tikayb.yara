rule TrojanProxy_Win32_Tikayb_A_2147628274_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Tikayb.A"
        threat_id = "2147628274"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tikayb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d1 ed 33 ea 2b cd 30 08 8a 10 4e 40 85 f6 75 e4}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 00 fa 00 00 7d 06 3b c3 74 db eb 04 3b c3 74 16}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 2c 05 c6 44 24 2d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

