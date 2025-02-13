rule Trojan_Win32_Peglegmorb_A_2147716674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Peglegmorb.A"
        threat_id = "2147716674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Peglegmorb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {bb 1a 7c e8 02 00 eb fe 60 8a 07 3c 00 74 09 b4 0e cd 10 83 c3 01 eb f1 61 c3}  //weight: 4, accuracy: High
        $x_2_2 = "SOMETHING HAS OVERWRITTEN YOUR MBR!" ascii //weight: 2
        $x_2_3 = {bb 00 20 40 00 ba 80 00 00 00 89 c7 89 de 89 d1 f3 a5}  //weight: 2, accuracy: High
        $x_2_4 = {c7 44 24 10 00 00 00 00 8d 45 e0 89 44 24 0c c7 44 24 08 00 02 00 00 8d 85 e0 fd ff ff 89 44 24 04 8b 45 e4 89 04 24 e8}  //weight: 2, accuracy: High
        $x_1_5 = "PEGGLECREW" ascii //weight: 1
        $x_1_6 = "(@CULTOFRAZER ON TWITTER)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

