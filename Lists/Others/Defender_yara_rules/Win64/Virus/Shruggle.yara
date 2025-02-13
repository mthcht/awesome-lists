rule Virus_Win64_Shruggle_A_2147607547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Shruggle.A"
        threat_id = "2147607547"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Shruggle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 72 75 67 20 2d 20 72 6f 79 20 67 20 62 69 76 48 [0-144] 6b ?? 65 ?? 72 ?? 6e ?? 65 ?? 6c ?? 33 ?? 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

