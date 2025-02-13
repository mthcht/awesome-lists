rule Ransom_MacOS_LockBit_A_2147845051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/LockBit.A"
        threat_id = "2147845051"
        type = "Ransom"
        platform = "MacOS: "
        family = "LockBit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {dd 00 94 e1 03 00 aa e0 03 80 52 02 00 80 d2 03 00 80 52 ?? ?? 00 94 1f 04 00 31}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0d 40 92 aa 6a 6a 38 ab 02 08 8b 6c 41 40 39 8a 01 0a 4a 6a 41 00 39 08 05 00 91 1f 01 09 eb 01 ff ff 54}  //weight: 1, accuracy: High
        $x_1_3 = "restore-my-files.txt" ascii //weight: 1
        $x_1_4 = "sodium_crit_enter" ascii //weight: 1
        $x_1_5 = "blake2b-ref.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MacOS_LockBit_F_2147916315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/LockBit.F!MTB"
        threat_id = "2147916315"
        type = "Ransom"
        platform = "MacOS: "
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 10 0f b6 70 14 40 f6 c6 01 74 56 0f b6 70 17 83 e6 1f 48 83 c6 ef 0f 1f 00 48 83 fe 08 77 3c 48 8d 0d 93 2c 1d 00 ff 24 f1}  //weight: 1, accuracy: High
        $x_1_2 = {76 2d 55 48 89 e5 48 83 ec 08 0f b6 48 17 83 e1 1f 48 83 f9 14 75 0a 48 8b 40 40 48 83 c4 08 5d c3 e8 16 ff ff ff 48 89 d8 48 83 c4 08 5d c3 48 89 44 24 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MacOS_LockBit_A_2147920067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/LockBit.A!MTB"
        threat_id = "2147920067"
        type = "Ransom"
        platform = "MacOS: "
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 41 0d 4a 8d 1d 40 92 0d 69 6d 38 29 61 0d 4a 2d 01 00 52 0c b4 03 29 aa 01 0a 4a 6b 01 0a 4a 0a ac 04 29 6c 01 0c 4a ed 03 0c aa ae 3d 48 d3 0e 69 6e 38 29 01 0e 4a}  //weight: 1, accuracy: High
        $x_1_2 = {aa 6a 6a 38 ab 02 08 8b 6c 41 40 39 8a 01 0a 4a 6a 41 00 39 08 05 00 91 1f 01 09 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

