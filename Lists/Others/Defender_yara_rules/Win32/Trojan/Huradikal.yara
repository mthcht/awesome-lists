rule Trojan_Win32_Huradikal_A_2147697776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Huradikal.A"
        threat_id = "2147697776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Huradikal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {79 66 75 5f 65 64 6f 74 67 e1}  //weight: 1, accuracy: High
        $x_1_2 = {3a 25 64 00 3a 2f 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2f 50 54 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 55 53 2f 00 00 00 00 2f 50 4f 2f 00 00 00 00 2f 57 53 2f 00 00 00 00 2f 50 43 2f 00 00 00 00 26 25 73 3d 00 00 00 00 3f 25 73 3d}  //weight: 1, accuracy: High
        $x_1_4 = "/system/cpass.bin" ascii //weight: 1
        $x_1_5 = {23 63 68 72 6f 6d 65 70 61 73 73 [0-4] 23 68 75 67 62 6f 74 6d 6f 64 [0-4] 23 67 61 6d 65 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

