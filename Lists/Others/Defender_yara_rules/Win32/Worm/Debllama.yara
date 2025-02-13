rule Worm_Win32_Debllama_B_2147614433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Debllama.B"
        threat_id = "2147614433"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Debllama"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff d7 83 ec 10 b9 08 00 00 00 8b d4 b8 34 36 40 00 8b 1d 18 11 40 00 6a 01 89 0a 8b 8d 68 ff ff ff 68 54 36 40 00 c7 85 4c ff ff ff ff ff ff ff 89 4a 04 8d 4d dc 51 c7 85 44 ff ff ff 0b 80 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "te molestan los Virus???" wide //weight: 1
        $x_1_3 = "shell\\open\\command=wind.exe" ascii //weight: 1
        $x_1_4 = "EL DIABLO" ascii //weight: 1
        $x_1_5 = "devil.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

