rule Virus_Win64_Virut_HNB_2147925660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Virut.HNB!MTB"
        threat_id = "2147925660"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Virut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6b c0 0f 50 0f b6 47 fc}  //weight: 2, accuracy: High
        $x_1_2 = {01 04 24 8d 7f f2}  //weight: 1, accuracy: High
        $x_1_3 = {8d 00 8b cc 1b 51 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

