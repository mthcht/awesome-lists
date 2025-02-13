rule PWS_Win32_Gaewe_A_2147651404_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Gaewe.A"
        threat_id = "2147651404"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Gaewe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 74 61 72 74 5c 44 4e 46 43 6f 6d 70 6f 6e 65 6e 74 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_2 = "commdll.dll" ascii //weight: 1
        $x_1_3 = {68 a0 86 01 00 e8 ?? ?? ?? ?? 6a 00 8d 55 f8 33 c0 e8 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

