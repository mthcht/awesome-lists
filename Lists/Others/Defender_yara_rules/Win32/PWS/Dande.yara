rule PWS_Win32_Dande_A_2147651317_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dande.A"
        threat_id = "2147651317"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dande"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 64 8b 05 18 00 00 00 8b 40 30 0f b6 40 02 89 45 fc 61 a1 ?? ?? ?? ?? 83 38 02 74 05 33 c0 89 45 fc}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 95 f8 fd ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 7e 07 8b 45 0c 89 30 33 db 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

