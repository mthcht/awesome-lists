rule Trojan_Linux_ZiChatBot_DA_2147968819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ZiChatBot.DA!MTB"
        threat_id = "2147968819"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ZiChatBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 38 5b a5 37 76 1f 6a f9 69 31 15 dc 59 f3 c6 50 cf f5 39 4e 6c ba 0a 94 03 1e 3c 15 c6 c9 e7 b1 f6 b7 0c b3 70 65 25 80 31 83 c8 ae d1 d7 4d c9 c7 58 68 ee 62 4c a2 c9 4a 2f 6c c6 e7 37 b2}  //weight: 1, accuracy: High
        $x_1_2 = {59 4f 5d e9 bb 0c 8a 84 6f 65 35 d5 b3 32 73 40 2b 15 ca 29 7c fa 21 ac f0 27 94 47 18 e3 13 2e 66 84 1d 0c 23 e0 98 aa 99 3e 0d af 51 c2 20 08 b0 67 33 0d 68 b7 f8 18 28 3c 2d d3 37 0a f2 ba}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

