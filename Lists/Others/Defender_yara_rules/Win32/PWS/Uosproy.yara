rule PWS_Win32_Uosproy_A_2147647541_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Uosproy.A"
        threat_id = "2147647541"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Uosproy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 06 e9 89 6e 01 83 e9 05 8d 54 24 08 52 c6 04 1f e9 89 4c 1f 01}  //weight: 1, accuracy: High
        $x_1_2 = {33 d0 81 f2 ?? ?? ?? ?? 89 90 ?? ?? ?? ?? 40 8d 94 01 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 7e da}  //weight: 1, accuracy: Low
        $x_1_3 = "%s?id=%s&mm=%s&level=%d&yyid=%d&biaoq=%s&ver=%s&yyver=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

