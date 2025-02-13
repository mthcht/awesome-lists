rule Virus_Win32_Geksone_EC_2147903827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Geksone.EC!MTB"
        threat_id = "2147903827"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Geksone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {60 9c e8 00 00 00 00 5d 81 ed 07 10 40 00 8d b5 5a 10 40 00 56 68 2c 01 00 00 ff b5 56 10 40 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

