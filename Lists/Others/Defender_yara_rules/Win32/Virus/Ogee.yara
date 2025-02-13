rule Virus_Win32_Ogee_A_2147681364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Ogee.A"
        threat_id = "2147681364"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Ogee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 09 00 00 00 6f 70 65 6e 67 6c 33 32 00 ff 54 24 30 e8 9e 04 00 00 54 c4 63 71 30 f2 6a a7 d3 ca 91 7f 48 dd 7c 8a 4a 69 e1 91 90 6b d1 45 d3 0d b4 a0 7c 49 3f 1a 1f f9 73 ac 0f a3 dd 88 fb d4 5f 55 7e 1d c1 78 c5 dd 2f b3 47 ef ee 9f 64 7a da 7d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

