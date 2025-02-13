rule Trojan_Win32_Kinob_A_2147682479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kinob.A"
        threat_id = "2147682479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kinob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 18 45 8b c5 83 e0 03 8a 5c 04 10 32 1c 29 0f 85 60 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b 46 08 03 c1 6a 00 50 e8 ?? ?? ?? ?? 83 c4 0c 8d 4c ?? ?? 51 68 ?? ?? ?? ?? c7 44 ?? ?? 1a 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 69 6e 6b 4f 69 6e 6b 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

