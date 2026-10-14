rule Backdoor_Linux_AVERAT_DA_2147979780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/AVERAT.DA!MTB"
        threat_id = "2147979780"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "AVERAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f8 01 19 c0 83 e0 b5 83 c0 78 89 44 24 78 89 d0 83 e0 02 83 f8 01 89 d0 45 19 ff 83 e0 04 41 83 e7 b6 41 83 c7 77 83 f8 01 89 d0 45 19 f6 83 e0 08 41 83 e6 bb 41 83 c6 72 83 f8 01 89 d0 45 19 ed 83 e0 10 41 83 e5 b5 41 83 c5 78 83 f8 01 89 d0 45 19 e4 83 e0 20 41 83 e4 b6 41 83 c4 77 83 f8 01 89 d0 19 db 83 e0 40 83 e3 bb 83 c3 72 83 f8 01 88 d0 45 19 db 83 e0 80 41 83 e3 b5 41 83 c3 78 3c 01 45 19 d2 81 e2 00 01 00 00 41 83 e2 b6 41 83 c2 77 83 fa 01 48 8b 94 24 a8 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {89 e5 48 83 c4 80 89 7d 8c 48 89 75 80 48 b8 3a 3d 37 0d 3a 0d 4e 7e 48 89 45 d0 48 b8 3a 47 48 37 67 47 7e 7a 48 89 45 d8 48 b8 48 63 0d 33 48 7a 23 00 48 89 45 e0 48 b8 23 40 4e 47 3a 23 40 4e 48 89 45 b0 48 b8 47 59 47 54 5e 6d 63 3b 48 89}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

