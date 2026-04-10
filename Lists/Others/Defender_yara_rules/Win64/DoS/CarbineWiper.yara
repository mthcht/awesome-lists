rule DoS_Win64_CarbineWiper_A_2147966703_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win64/CarbineWiper.A!dha"
        threat_id = "2147966703"
        type = "DoS"
        platform = "Win64: Windows 64-bit platform"
        family = "CarbineWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 2e 73 73 64 5f 77 69 70 65 5f 66 69 6c 6c 2e 74 6d 70}  //weight: 1, accuracy: High
        $x_1_2 = {20 55 73 65 20 2d 2d 66 6f 72 63 65 20 74 6f 20 63 6f 6e 66 69 72 6d 20 53 53 44 20 77 69 70 65 00}  //weight: 1, accuracy: High
        $x_1_3 = " Failed to delete filler file: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

