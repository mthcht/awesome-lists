rule Ransom_MacOS_Mabouia_A_2147745270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/Mabouia.A!MTB"
        threat_id = "2147745270"
        type = "Ransom"
        platform = "MacOS: "
        family = "Mabouia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "creativecode.com.br" ascii //weight: 1
        $x_1_2 = "mabouia_Decrypter" ascii //weight: 1
        $x_1_3 = "/Desktop/ransom" ascii //weight: 1
        $x_1_4 = "/mabouia/catcher.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MacOS_Mabouia_B_2147911018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/Mabouia.B!MTB"
        threat_id = "2147911018"
        type = "Ransom"
        platform = "MacOS: "
        family = "Mabouia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 28 4c 8d 45 b0 4c 89 ef 4c 89 e6 4c 89 fa 48 8b 4d a8 4d 89 c7 e8 aa fe ff ff 89 c3 be 20 00 00 00 4c 89 ff e8 c1 8b 00 00 4c 3b 75 d0}  //weight: 1, accuracy: High
        $x_1_2 = {73 67 40 88 75 b0 c6 45 b1 00 c6 45 b2 01 c6 45 b3 01 c7 45 ec 00 00 00 00 48 c7 45 e4 00 00 00 00 48 c7 45 dc 00 00 00 00 48 c7 45 d4 00 00 00 00 48 c7 45 cc 00 00 00 00 48 c7 45 c4 00 00 00 00 48 c7 45 bc 00 00 00 00 48 c7 45 b4 00 00 00 00 48 8d 75 b0 e8 38 ff ff ff 48 3b 5d f0 75 0e 31 c0 48 83 c4 48 5b 5d c3 e8 e6 81 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

