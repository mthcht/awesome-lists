rule Ransom_Linux_Hive_A_2147817005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Hive.A"
        threat_id = "2147817005"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Hive"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 89 84 24 90 01 00 00 48 8b ?? 24 78 01 00 00 48 83 ?? 03 48 8b ?? 24 80 01 00 00 75 21 0f b7 ?? 66 33 84 24 90 01 00 00 8a ?? 02 32 8c 24 92 01 00 00 0f b6 c9 66 09 c1 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 50 48 8b 44 24 50 8b 80 ?? ?? ?? ?? b9 ?? ?? ?? ?? 31 c8 89 44 24 08 48 83 ?? 04 75 0c 8b ?? 3b 44 24 08 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = "vmdk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Hive_A_2147831786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Hive.A!MTB"
        threat_id = "2147831786"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Hive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 02 30 8c 04 90 00 00 00 48 8d 48 01 48 89 c8 48 83 f9 04 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 ef e8 a3 0f 04 00 88 84 1c 50 01 00 00 48 ff c3 48 83 fb 08 75 e8}  //weight: 1, accuracy: High
        $x_1_3 = "vmdk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Hive_B_2147851014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Hive.B!MTB"
        threat_id = "2147851014"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Hive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vim-cmd vmsvc/power.off" ascii //weight: 1
        $x_1_2 = "+encrypt %s" ascii //weight: 1
        $x_1_3 = "hive" ascii //weight: 1
        $x_1_4 = {74 74 70 3a 2f 2f [0-88] 2e 6f 6e 69 6f 6e 2f}  //weight: 1, accuracy: Low
        $x_1_5 = "HOW_TO_DECRYPT.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Hive_C_2147891315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Hive.C!MTB"
        threat_id = "2147891315"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Hive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 a9 e7 1c 8a e5 be 64 06 a5 e0 72 36 71 73 4f 16 5f 06 97 d6 b4 92 a1 51 25 fb 54 43 c7 49 24 0c 33 bc 04 7b 47 fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Hive_E_2147913714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Hive.E!MTB"
        threat_id = "2147913714"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Hive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 85 69 26 00 8b 30 48 85 f6 0f 84 48 01 00 00 48 c1 e6 20 48 83 ce 02 48 8d 8c 24 80 00 00 00 ba 01 00 00 00 31 c0 48 89 f3 4c 8b 74 24 70 48 8b 6c 24 68 44 8a 6c 24 06 4c 8b 64 24 60 eb 23}  //weight: 1, accuracy: High
        $x_1_2 = {eb 40 ff 15 4b 48 26 00 8b 38 48 89 fb 48 c1 e3 20 48 83 cb 02 48 89 9c 24 b0 00 00 00 48 c7 84 24 a8 00 00 00 01 00 00 00 e8 6d c7 02 00 3c 23 75 4d 48 8d bc 24 b0 00 00 00 e8 cc 1b 00 00 4c 89 f9 48 85 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Hive_L_2147913717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Hive.L!MTB"
        threat_id = "2147913717"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Hive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 39 d6 0f 86 30 03 00 00 8a 04 11 41 88 04 3c 48 ff c7 48 ff c2 48 89 d0 31 d2 48 f7 f6 48 83 ff 04 75 dc}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 03 48 83 f8 05 72 0f 49 f7 e4 48 85 c0 74 07 48 8b 7b 10 41 ff d5 48 8b 43 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Hive_M_2147923441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Hive.M!MTB"
        threat_id = "2147923441"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Hive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 07 48 83 f8 05 72 ?? 48 8b 47 18 48 85 c0 74 ?? 48 8b 4f 10 48 8d 0c c1 48 83 c1 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 5c 24 10 49 89 ef ?? ?? 6c 24 18 48 89 df ff 55 00 48 83 7d 08 00 4c 89 fd 74 ?? 48 89 df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

