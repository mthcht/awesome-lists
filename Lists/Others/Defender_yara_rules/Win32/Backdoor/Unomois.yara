rule Backdoor_Win32_Unomois_A_2147657466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Unomois.A"
        threat_id = "2147657466"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Unomois"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "me0hoi" wide //weight: 1
        $x_1_2 = {8b d8 83 e1 03 c1 e1 04 c1 eb 04 0b d9}  //weight: 1, accuracy: High
        $x_1_3 = {88 07 88 4f 01 83 c5 03 83 c7 04 83 ea 01}  //weight: 1, accuracy: High
        $x_1_4 = {0f b6 50 01 0f b6 78 02 83 e2 0f 03 d2 03 d2 c1 ef 06 0b d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

