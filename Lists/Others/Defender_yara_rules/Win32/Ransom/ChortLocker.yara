rule Ransom_Win32_ChortLocker_A_2147933724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ChortLocker.A"
        threat_id = "2147933724"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ChortLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 24 0f b6 14 02 31 d5 8b 54 24 10 95 88 04 3a 95 47 8b 6c 24 ?? 89 d0 8b 54 24 24 39 f9 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

