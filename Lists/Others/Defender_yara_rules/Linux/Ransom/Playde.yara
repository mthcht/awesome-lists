rule Ransom_Linux_Playde_A_2147919805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Playde.A!MTB"
        threat_id = "2147919805"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Playde"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 85 00 ff ff ff 48 89 d6 48 89 c7 e8 13 7d 00 00 ?? ?? ?? ?? ?? ?? ?? ba 10 00 00 00 be 00 00 00 00 48 89 c7 e8 ee 7b 00 00 48 8b 85 00 ff ff ff ?? ?? ?? ?? ?? ?? ?? 48 89 c7 e8 f1 c8 ff ff 48 89 85 08 ff ff ff 48 83 bd 08 ff ff ff 00 75 0a b8 ff ff ff ff e9 69 03 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 5a 2a 97 d1 41 80 eb f9 81 e2 49 5f b1 e3 ?? ?? ?? ?? ?? ?? ?? 41 d0 c3 41 80 f3 36 81 cb 63 cd aa 8e 48 99 41 f6 db f6 d3 66 81 c3 fa e6 45 32 c3 ?? ?? ?? ?? ?? ?? ?? ?? 4c 03 dc 48 0f ab dd 0f 92 c0 48 81 e2 82 c8 2c 0f 49 8b 84 d3 f0 fb dd 97 53 48 89 84 56 f4 7e f7 e5 8b cb 46 0f b6 9c 0a 7c bf fb f2 66 c7 84 14 84 bf fb f2 ff 54 45 32 d8 41 f6 d3 48 d3 a4 14 7e bf fb f2 c0 bc 14 83 bf fb f2 a6 e8 05 e5 1e 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 45 f8 48 89 d6 48 89 c7 e8 27 59 00 00 48 8b 45 f8 ?? ?? ?? ?? ?? ?? ?? 48 89 c7 e8 ea 57 00 00 48 8b 45 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

