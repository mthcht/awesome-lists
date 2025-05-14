rule Trojan_Win32_BroomStick_Z_2147941378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BroomStick.Z!MTB"
        threat_id = "2147941378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BroomStick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b f7 7c db 5f 5e 5b}  //weight: 1, accuracy: High
        $x_1_2 = {8b 85 10 ff ff ff 8b 00 8b 70 18 8d 45 a8}  //weight: 1, accuracy: High
        $x_1_3 = {85 c0 74 25 8d 3c 40 03 ff 83 ef 06 8b d3}  //weight: 1, accuracy: High
        $x_1_4 = {8b 5d d8 ff 00 33 f6 8b 00 0f b6 08}  //weight: 1, accuracy: High
        $x_1_5 = {8b ce ff 15 [0-32] 8b cf ff d6 8b 85 28 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

