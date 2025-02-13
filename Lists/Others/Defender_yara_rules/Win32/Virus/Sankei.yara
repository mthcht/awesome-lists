rule Virus_Win32_Sankei_A_2147602580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sankei.A"
        threat_id = "2147602580"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sankei"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 15 b4 16 43 00 8b d8 68 ?? ?? ?? ?? 53 ff 15 b8 16 43 00 a3 47 a0 43 00 68 00 00 00 f0 6a 01 6a 00 6a 00 68 43 a0 43 00 ff 15 47 a0 43 00 68 ?? ?? ?? ?? 53 ff 15 b8 16 43 00 a3 47 a0 43 00 68 3b a0 43 00 6a 00 6a 00 68 03 80 00 00 ff 35 43 a0 43 00 ff 15 47 a0 43 00 68 ?? ?? ?? ?? 53 ff 15 b8 16 43 00 a3 47 a0 43 00 6a 00 6a 20 68 75 90 43 00 ff 35 3b a0 43 00 ff 15 47 a0 43 00 68 ?? ?? ?? ?? 53 ff 15 b8 16 43 00 a3 47 a0 43 00 68 3f a0 43 00 6a 00 ff 35 3b a0 43 00 68 01 68 00 00 ff 35 43 a0 43 00 ff 15 47 a0 43 00 68 ?? ?? ?? ?? 53 ff 15 b8 16 43 00 a3 47 a0 43 00 33 c0 68 f1 9f 43 00 68 ea 90 43 00 50 6a 01 50 ff 35 3f a0 43 00 ff 15 47 a0 43 00 85 c0 eb 05 e9 d6 95 fc ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

