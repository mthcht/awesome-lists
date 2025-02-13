rule Virus_Win64_Phdet_A_2147684803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Phdet.A"
        threat_id = "2147684803"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 3f b0 8f b0 e8 ?? ?? ?? ?? 0f b7 08 81 f9 70 17 00 00 0f 8c ?? ?? ?? ?? 81 f9 72 17 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "9DD6AFA1-8646-4720-836B-EDCB10858701" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

