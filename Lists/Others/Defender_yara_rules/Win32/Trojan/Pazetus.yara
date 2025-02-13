rule Trojan_Win32_Pazetus_RD_2147894976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pazetus.RD!MTB"
        threat_id = "2147894976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pazetus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {da 97 68 ce e7 6c ae f8 c6 dd 7a 51 f8 fb a0 9d 0c 14 8d 20 14 02 92 9c 6c 82 e8 cd 3d d0 e4 33 c9 c7 17 e2 01 18 ca fc 8a de de 75 9e 5a 06 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

