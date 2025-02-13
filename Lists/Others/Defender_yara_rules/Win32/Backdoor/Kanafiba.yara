rule Backdoor_Win32_Kanafiba_A_2147656113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kanafiba.A"
        threat_id = "2147656113"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kanafiba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 40 8d 1c 85 ?? ?? 45 00 83 3d ?? ?? 45 00 00 75 41 68 6d 27 00 00 8d 45 f8}  //weight: 1, accuracy: Low
        $x_1_2 = "KAHFIUNBAUSNAK" ascii //weight: 1
        $x_1_3 = {c7 45 ec 22 c8 00 00 33 c0 55 68 ?? ?? 45 00 64 ff 30 64 89 20 b2 01 a1}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 70 cc 50 c7 da 30 16 ae 33 7e fd e1 43 83 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

