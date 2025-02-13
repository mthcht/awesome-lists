rule Backdoor_Linux_Mettle_A_2147822179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mettle.A!MTB"
        threat_id = "2147822179"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mettle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c3 71 84 0d 00 c7 45 90 00 00 00 00 8d 7d 94 b9 0a 00 00 00 31 c0 f3 aa 8d 7d b3 b9 35 00 00 00 f3 aa 8d 7d 9e b9 15 00 00 00 f3 aa be 01 00 00 00 3b 75 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

