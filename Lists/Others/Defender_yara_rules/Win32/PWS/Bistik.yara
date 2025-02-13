rule PWS_Win32_Bistik_A_2147656927_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Bistik.A"
        threat_id = "2147656927"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Bistik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {be 88 00 00 00 57 56 6a 01 53 e8 ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 83 c4 14 33 c0 8a c8 80 c1 ?? 30 0c 18 40 3b c6 72 f3 6a 01 58}  //weight: 2, accuracy: Low
        $x_1_2 = {89 5d fc 8d 45 ?? 66 0f be 91 ?? ?? ?? ?? c1 e2 02 66 89 10 41 40 40 83 f9 ?? 7c ea 8d 45 ?? c7 45 e0 4a 00 00 00 89 45}  //weight: 1, accuracy: Low
        $x_1_3 = "IE:Password-Protected sites" ascii //weight: 1
        $x_1_4 = {61 70 70 6d 67 6d 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

