rule Worm_Win32_Rodvir_2147596654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rodvir"
        threat_id = "2147596654"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rodvir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 85 c0 7e 1a 8a 93 70 50 40 00 30 16 46 43 81 e3 07 00 00 80 79 05 4b 83 cb f8 43 48 75 e6}  //weight: 1, accuracy: High
        $x_1_2 = {81 74 24 04 36 63 02 16 6a 00 53 e8 ?? ?? ff ff 3b 44 24 04 72 3c 6a 02 6a 00 8b 44 24 0c f7 d8 50 53 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {81 75 f8 36 63 02 16 6a 00 53 e8 ?? ?? ff ff 3b 45 f8 0f 82 b1 00 00 00 6a 02 6a 00 8b 45 f8 f7 d8 50 53 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

