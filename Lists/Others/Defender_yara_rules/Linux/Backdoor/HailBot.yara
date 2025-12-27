rule Backdoor_Linux_HailBot_A_2147946729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/HailBot.A!MTB"
        threat_id = "2147946729"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "HailBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 03 b9 8f 00 00 00 00 09 f8 20 03 00 00 00 00 18 00 bc 8f 06 00 40 14 21 90 40 00 21 c8 c0 03 09 f8 20 03 21 20 20 02 18 00 bc 8f 21 90 22 02}  //weight: 1, accuracy: High
        $x_1_2 = {23 80 51 02 00 00 70 a2 21 28 20 02 21 20 a0 02 21 c8 e0 02 09 f8 20 03 21 30 00 02 00 00 43 82 01 00 c2 26 18 00 bc 8f 21 b0 50 00 07 00 60 10 21 98 b0 02 01 00 51 26}  //weight: 1, accuracy: High
        $x_1_3 = {f0 02 a3 8f 10 00 02 24 f4 02 a5 8f c0 02 a6 8f f8 02 b9 8f 14 00 a2 af 10 00 a3 af 21 20 20 02 09 f8 20 03 21 38 00 00 18 00 bc 8f 29 00 40 04 ff ff 72 26 05 00 02 24 fc 02 b0 8f 24 00 a2 af}  //weight: 1, accuracy: High
        $x_1_4 = {f4 02 a2 8f 00 00 00 ae 04 00 10 26 fc ff 02 16 21 20 c0 02 1c 00 a2 8e 04 03 a3 8f 25 10 57 00 fc 02 a5 8f 1c 00 a2 ae 28 00 a0 af 10 00 a3 af 21 30 00 00 21 c8 c0 03 09 f8 20 03 21 38 00 00 21 18 40 00 ff ff 02 24 18 00 bc 8f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

