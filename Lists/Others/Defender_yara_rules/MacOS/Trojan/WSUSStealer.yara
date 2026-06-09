rule Trojan_MacOS_WSUSStealer_DA_2147971197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/WSUSStealer.DA!MTB"
        threat_id = "2147971197"
        type = "Trojan"
        platform = "MacOS: "
        family = "WSUSStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c9 02 b9 a9 c5 82 52 c9 01 b0 72 49 cd 02 b9 09 e5 8c 52 a9 a6 a0 72 49 c1 02 b9 e9 67 84 52 49 c0 a4 72 49 c5 02 b9 49 23 81 52 49 88 a0 72 49 b9 02 b9 29 1e 84 52 09 cc a6 72 49 bd 02 b9 89 4b 9e 52 29 80 af 72 49 b1 02 b9 69 50 97 52 49 60 bc 72 49 b5 02 b9 c9 71 9b 52 c9 45 b8 72 49}  //weight: 1, accuracy: High
        $x_1_2 = {a4 72 49 51 05 b9 69 73 87 52 c9 d6 bf 72 49 55 05 b9 49 da 84 52 a9 dd ab 72 49 59 05 b9 29 51 86 52 69 58 a0 72 49 5d 05 b9 09 cc 94 52 69 60 a5 72 49 61 05 b9 e9 ae 82 52 29 26 ab 72 49 65 05 b9 c9 43 90 52 69 ee b6 72 49 69 05 b9 a9 d4 91 52 29 6a a8 72 49 6d 05 b9 89 dd 92}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

