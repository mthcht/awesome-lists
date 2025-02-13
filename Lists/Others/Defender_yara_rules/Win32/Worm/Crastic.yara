rule Worm_Win32_Crastic_A_2147688028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Crastic.gen!A"
        threat_id = "2147688028"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Crastic"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 18 8a 0c 39 32 08 48 88 48 01 fe ca 4e 75 e6 32 d2 b8}  //weight: 1, accuracy: High
        $x_1_2 = {7f 11 7c 08 81 ff a0 86 01 00 73 07 bf}  //weight: 1, accuracy: High
        $x_1_3 = {83 bd e8 fe ff ff 10 8b cf 73 06 8d 8d d4 fe ff ff 80 3c 01 5c 75 0a 42 83 fa 01 0f 87}  //weight: 1, accuracy: High
        $x_1_4 = {6a 27 53 ff 15 ?? ?? ?? ?? 3b c3 75 2c 8d 85 ?? ?? ?? ?? 8d 50 01 8a 08 40 3a cb 75 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

