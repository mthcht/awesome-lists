rule Virus_Linux_Thebe_2147649741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Linux/Thebe"
        threat_id = "2147649741"
        type = "Virus"
        platform = "Linux: Linux platform"
        family = "Thebe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {93 e8 3f 00 00 00 3d 7f 45 4c 46 74 03 31 c0 c3}  //weight: 1, accuracy: High
        $x_1_2 = "RSBRBBRQ1" ascii //weight: 1
        $x_1_3 = {8b 30 01 fe 8b 16 81 fa 2e 64 74 6f 74 05 e2 e8 31 c0 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

