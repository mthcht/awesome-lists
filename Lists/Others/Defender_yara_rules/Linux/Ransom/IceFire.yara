rule Ransom_Linux_IceFire_A_2147843300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/IceFire.A!MTB"
        threat_id = "2147843300"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "IceFire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/iFire-readme.txt" ascii //weight: 1
        $x_1_2 = ".iFire" ascii //weight: 1
        $x_1_3 = "./boot./dev./etc./lib./proc./srv./sys./usr./var./run" ascii //weight: 1
        $x_1_4 = {0f a2 41 89 c3 31 c0 81 fb 47 65 6e 75 0f 95 c0 41 89 c1 81 fa 69 6e 65 49 0f 95 c0 41 09 c1 81 f9 6e 74 65 6c 0f 95 c0 41 09 c1 0f 84 87 00 00 00 81 fb 41 75 74 68 0f 95 c0 41 89 c2 81 fa 65 6e 74 69 0f 95 c0 41 09 c2 81 f9 63 41 4d 44 0f 95 c0 41 09 c2}  //weight: 1, accuracy: High
        $x_1_5 = {c6 45 a0 29 c6 45 a1 c0 c6 45 a2 f6 c6 45 a3 94 c6 45 a4 fd c6 45 a5 fd c6 45 a6 fd c6 45 a7 fd c6 45 a8 43 c6 45 a9 6f c6 45 aa 6d c6 45 ab 53 c6 45 ac 70 c6 45 ad 65 c6 45 ae 63 c6 45 af 3d c6 45 b0 43 c6 45 b1 3a c6 45 b2 5c c6 45 b3 57 c6 45 b4 69 c6 45 b5 6e c6 45 b6 64 c6 45 b7 6f c6 45 b8 77 c6 45 b9 73 c6 45 ba 5c c6 45 bb 73 c6 45 bc 79 c6 45 bd 73 c6 45 be 74 c6 45 bf 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

