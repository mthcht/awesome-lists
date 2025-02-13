rule Backdoor_MacOS_Meddlingmetal_A_2147745260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Meddlingmetal.A"
        threat_id = "2147745260"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Meddlingmetal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 ea 08 83 e2 3f 41 33 0c 92 89 c2 c1 ea 10 83 e2 3f c1 e8 18 83 e0 3f 41 33 0c 93 44 89 ca c1 c2 1c 33 94 37 8c 00 00 00 41 33 0c 86 89 d0 83 e0 3f 41 33 0c 87 89 d0 c1 e8 08 83 e0 3f 41 33 0c 84 89 d0 c1 e8 10 83 e0 3f 41 33 4c 85 00 c1 ea 18}  //weight: 1, accuracy: High
        $x_1_2 = {c1 ea 08 83 e2 3f 45 33 14 91 89 f2 c1 ea 10 83 e2 3f c1 ee 18 83 e6 3f 45 33 14 93 89 ca c1 c2 1c 42 33 94 00 84 00 00 00 45 33 14 b6 89 d6 83 e6 3f 45 33 14 b7 89 d6 c1 ee 08 83 e6 3f 45 33 14 b4 89 d6 c1 ee 10 83 e6 3f c1 ea 18}  //weight: 1, accuracy: High
        $x_4_3 = "MSF_LICENSE" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

