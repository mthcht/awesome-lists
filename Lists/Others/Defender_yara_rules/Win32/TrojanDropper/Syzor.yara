rule TrojanDropper_Win32_Syzor_A_2147621516_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Syzor.A"
        threat_id = "2147621516"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Syzor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {37 2c 6d 73 95 65 83 d4 1c 08 12 cb 40 16 5b c4 d9 07 61 00 a7 a3 36 13 c0 c7 32 a6 77 6a 00 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

