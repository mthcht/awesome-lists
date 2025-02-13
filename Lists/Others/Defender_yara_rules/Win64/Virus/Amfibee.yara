rule Virus_Win64_Amfibee_A_2147654638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Amfibee.A"
        threat_id = "2147654638"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Amfibee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 48 8d 0d 00 00 00 00 58 c3 5f e8 63 ff ff ff e8 eb ff ff ff 67 e3 0c 48 8b 73 10 48 ad 48 8b 68 20 eb 07 8b 73 08 ad 8b 68 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

