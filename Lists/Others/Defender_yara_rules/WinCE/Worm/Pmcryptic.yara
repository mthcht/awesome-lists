rule Worm_WinCE_Pmcryptic_A_2147616468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:WinCE/Pmcryptic.A"
        threat_id = "2147616468"
        type = "Worm"
        platform = "WinCE: Windows CE platform"
        family = "Pmcryptic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 60 d0 e7 05 70 d2 e7 07 60 26 e0 04 60 c0 e7 01 40 84 e2 01 50 85 e2 03 00 35 e1 00 50 a0 03 01 00 54 e1 f5 ff ff ba f0 80 bd e8}  //weight: 1, accuracy: High
        $x_1_2 = {08 30 a0 e3 1c 20 4f e2 00 20 42 e2 01 1a 8f e2 ae 1f 81 e2 20 00 8f e2 00 00 80 e2 00 10 41 e0 14 00 8f e2 00 00 80 e2 c1 ff ff eb 08 00 8f e2 00 00 80 e2 00 f0 a0 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

