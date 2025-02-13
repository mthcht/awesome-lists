rule TrojanSpy_MacOS_Bartacomabelli_A_2147743630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MacOS/Bartacomabelli.A"
        threat_id = "2147743630"
        type = "TrojanSpy"
        platform = "MacOS: "
        family = "Bartacomabelli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0b 80 f1 aa 88 08 48 ff c3 48 ff c0 49 ff ce 75 ee}  //weight: 1, accuracy: High
        $x_2_2 = {c6 de d8 c5 99 cc d2 d9 [0-16] d9 d3 9d d2 d9 db cd d0 [0-24] 84 c5 c4 c3 [0-16] c5 c4}  //weight: 2, accuracy: Low
        $x_2_3 = {85 ff d9 cf d8 d9 85 f9 [0-16] c2 cb d8 cf [0-16] ce 85}  //weight: 2, accuracy: Low
        $x_2_4 = {e9 c5 c4 de cf c4 de d9 [0-16] 85 e7 cb c9 e5 f9 85 eb [0-16] da da f9 de c5 d8 cf aa}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

