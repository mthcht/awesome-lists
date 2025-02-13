rule TrojanDropper_Win32_Jevafus_A_2147609498_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Jevafus.A"
        threat_id = "2147609498"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Jevafus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff ff e9 a2 01 00 00 49 0f f6 3c cf 75 ee c0 0f 31 8b c8 0f 31 2b c8 f7 d1 81 f9 00 50 00 00 7f fe 0f 31 8b c8 0f 31 2b c8 f7 d1 81 f9 00 50 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {7f fe d6 0f 88 dd 01 00 00 0f 89 d7 01 00 00 3e c1 c3 05 c1 cb 05 36 0f 8a 01 02 00 00 0f 8b fb 01 00 00 5b e8 0b 00 00 00 72 65 67 69 73 74 65 72 65 64}  //weight: 1, accuracy: High
        $n_10_3 = "(C) Grandsoft Corp. Ltd." wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

