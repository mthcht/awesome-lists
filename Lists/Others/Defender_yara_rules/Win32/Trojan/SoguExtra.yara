rule Trojan_Win32_SoguExtra_B_2147957204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SoguExtra.B"
        threat_id = "2147957204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SoguExtra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 07 b2 53}  //weight: 1, accuracy: High
        $x_1_2 = {ce c9 ca bd}  //weight: 1, accuracy: High
        $x_1_3 = {43 c9 fc 54}  //weight: 1, accuracy: High
        $x_1_4 = {65 00 ba fa}  //weight: 1, accuracy: High
        $x_1_5 = {18 81 ed 44}  //weight: 1, accuracy: High
        $x_1_6 = {3d c6 fb 99}  //weight: 1, accuracy: High
        $x_1_7 = {75 e7 11 1a}  //weight: 1, accuracy: High
        $x_1_8 = {3d 3c c3 c2}  //weight: 1, accuracy: High
        $x_1_9 = {f3 21 06 82}  //weight: 1, accuracy: High
        $x_1_10 = {a8 2c a6 2f}  //weight: 1, accuracy: High
        $x_1_11 = {3a fd 80 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

