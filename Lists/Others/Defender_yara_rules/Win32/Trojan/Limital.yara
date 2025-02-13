rule Trojan_Win32_Limital_A_2147696569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Limital.A"
        threat_id = "2147696569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Limital"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 85 b6 00 00 00 8b 85 ?? ?? ?? ?? 3b 46 40 0f 85 a7 00 00 00 8b b5 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 85 c0 74 39 56 ff 15 ?? ?? ?? ?? 85 c0 75 2e}  //weight: 2, accuracy: Low
        $x_1_2 = {56 33 c9 8b 45 08 8d 04 48 be ?? ?? 00 00 66 31 30 41 83 f9 32 7c ec 4a 75 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

