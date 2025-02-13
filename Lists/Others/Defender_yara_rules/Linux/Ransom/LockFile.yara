rule Ransom_Linux_LockFile_A_2147926124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/LockFile.A!MTB"
        threat_id = "2147926124"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 20 48 89 50 08 48 89 73 08 49 8b 40 08 49 03 47 08 48 3b 44 24 10 0f 85 ca ?? ?? ?? 4c 89 c2 48 89 ee 4c 89 ef e8 98 ?? ?? ?? 48 8b 44 24 48 48 89 44 24 18 48 8b 40 08 48 85 c0 0f 84 ?? ?? ?? ?? 4c 8b 64 24 40 48 89 6c 24 08 49 8b 5c 24 08}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 ff e8 fb ?? ?? ?? 31 d2 be 05 f5 54 00 4c 89 ff b9 05 00 00 00 e8 d7 ?? ?? ?? be a3 f4 54 00 48 8d bc 24 00 03 00 00 48 85 c0 b8 a7 f4 54 00 48 0f 45 f0 e8 a9 ?? ?? ?? 48 8b bc 24 60 05 00 00 48 8d 84 24 70 05 00 00 48 39 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

