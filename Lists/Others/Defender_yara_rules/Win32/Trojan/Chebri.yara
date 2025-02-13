rule Trojan_Win32_Chebri_B_2147651790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chebri.B"
        threat_id = "2147651790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chebri"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 fc 21 8a 4d 10 88 4d fd 6a 06 8d 55 f8 52 8b 45 08 50 e8}  //weight: 1, accuracy: High
        $x_1_2 = {68 21 4e 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 ?? ba 01 00 00 00 85 d2 74 0d}  //weight: 1, accuracy: Low
        $x_1_3 = "DANCHODANCHEV_AND_BRIANKREBS_GOT_MARRIED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

