rule Virus_Win32_Hematite_A_2147720955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Hematite.gen!A"
        threat_id = "2147720955"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Hematite"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 ef ff 75 10 ff 95 ?? ?? 00 00 ff 75 ?? ff 95 ?? ?? 00 00 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 4d ?? 81 c1 ?? ?? 00 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

