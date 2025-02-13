rule Virus_Win64_Svafa_A_2147653714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Svafa.A"
        threat_id = "2147653714"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Svafa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c8 40 01 00 55 54 5e 56 5a 48 83 ec 28 ff 57 18 48 95 48 33 db 55 53 53 6a 03 48 83 ec 20 4d 33 c9 4d 33 c0 6a 03 5a 48 8d 4e 2c ff 57 30 48 83 c4 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

