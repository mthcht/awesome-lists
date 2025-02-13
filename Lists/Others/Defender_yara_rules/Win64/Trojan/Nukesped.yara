rule Trojan_Win64_Nukesped_MA_2147832890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Nukesped.MA!MTB"
        threat_id = "2147832890"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Nukesped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {45 0f b7 ce 66 44 0f b6 cf 4c 0f b7 cc 48 ff c9 41 80 fd 10 41 f6 d1 48 33 d9 44 1a cb 48 81 ef 08 00 00 00 44 0f b7 ce 48 89 0f 45 2a cf 49 81 e8 04 00 00 00 44 32 c9 4c 0f bf cc 41 81 c1 2f 76 91 31 45 8b 08 41 80 fb 60 49 85 f9 f8 44 33 cb e9 fa fe 0a 00}  //weight: 3, accuracy: High
        $x_3_2 = {66 0f ba e6 2c 48 f7 d2 48 c1 ca 07 66 d3 ee 66 c1 e6 69 48 ff c6 4c 33 c2 41 12 f1 48 81 ef 08 00 00 00 48 89 17 66 be 03 06 66 40 0f be f6 40 d2 e6 49 81 e9 04 00 00 00 41 8b 31 e9 65 35 fc ff}  //weight: 3, accuracy: High
        $x_2_3 = {f0 00 22 20 0b 02 0a 00 00 ?? 07 00 00 5c 03 00 00 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

