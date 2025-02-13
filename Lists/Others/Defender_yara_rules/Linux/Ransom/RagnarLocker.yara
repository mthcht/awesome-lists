rule Ransom_Linux_RagnarLocker_B_2147812804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/RagnarLocker.B!MTB"
        threat_id = "2147812804"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "RagnarLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".README_TO_RESTORE" ascii //weight: 1
        $x_1_2 = "File Locked:%s PID:%d" ascii //weight: 1
        $x_1_3 = ".crypted" ascii //weight: 1
        $x_1_4 = "wrkman.log" ascii //weight: 1
        $x_1_5 = "Usage:%s [-m (10-20-25-33-50) ] Start Path" ascii //weight: 1
        $x_1_6 = {48 8b 3d bc ?? 20 00 48 85 ff 74 11 ba 92 01 00 00 be ?? ?? ?? ?? 31 c0 e8 ?? ?? fe ff 48 8b 3d 9f ?? 20 00 e8 ?? ?? fe ff 45 31 ed 48 83 c9 ff 48 89 df 44 88 e8 f2 ae 48 f7 d1 44 8d 61 1f 4d 63 e4 4c 89 e7 e8 ?? ?? fe ff 4c 89 e1 48 89 c5 48 89 c7 44 88 e8 48 89 da be 48 ed 41 00 f3 aa b9 ?? ?? ?? ?? 48 89 ef}  //weight: 1, accuracy: Low
        $x_1_7 = {48 89 e0 80 30 5c 48 ff c0 4c 39 e0 75 ?? ba 40 00 00 00 48 89 ee e8 ?? ?? ff ff c7 03 67 e6 09 6a c7 43 04 85 ae 67 bb 48 89 e8 c7 43 08 72 f3 6e 3c c7 43 0c 3a f5 4f a5 c7 43 10 7f 52 0e 51 c7 43 14 8c 68 05 9b c7 43 18 ab d9 83 1f c7 43 1c 19 cd e0 5b 48 c7 43 60 00 00 00 00 80 30 6a 48 ff c0 4c 39 e0 75 ?? 48 89 ee}  //weight: 1, accuracy: Low
        $x_1_8 = {55 31 ed 89 e8 53 48 81 ec e8 01 00 00 48 8d 7c 24 0c 48 c7 04 24 41 00 00 00 4c 8d 64 24 0c f3 ab 48 8d 7c 24 2c b1 08 f3 ab 48 8d 7c 24 4c b1 08 f3 ab 48 8d bc 24 ec 00 00 00 b1 3d f3 ab bf 01 03 00 00 e8 ?? ?? ff ff 48 85 c0 48 89 c3 75 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Ransom_Linux_RagnarLocker_C_2147891956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/RagnarLocker.C!dha"
        threat_id = "2147891956"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "RagnarLocker"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "error encrypt: %s" ascii //weight: 1
        $x_1_2 = "If you are reading this message, it means that: " ascii //weight: 1
        $x_1_3 = "D A R K    A N G E L S   T E A M  !" ascii //weight: 1
        $x_1_4 = "Cooperating with the FBI, CISA and so on" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Linux_RagnarLocker_D_2147892374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/RagnarLocker.D!MTB"
        threat_id = "2147892374"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "RagnarLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".RGNR_ESXI" ascii //weight: 1
        $x_1_2 = "Usage: %s -sleep N-min and/or /path/to/be/encrypted" ascii //weight: 1
        $x_1_3 = "RGNR_NOTES" ascii //weight: 1
        $x_1_4 = ".vmdk" ascii //weight: 1
        $x_1_5 = "ENC_FILES" ascii //weight: 1
        $x_1_6 = ".onion/client/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

