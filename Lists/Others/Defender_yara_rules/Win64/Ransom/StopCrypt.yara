rule Ransom_Win64_StopCrypt_GVA_2147956711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/StopCrypt.GVA!MTB"
        threat_id = "2147956711"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 54 24 28 48 89 d1 48 f7 ea 48 01 ca 48 c1 fa 05 48 6b d2 3e 48 89 ce 48 29 d1 88 4c 34 18 e9 68 ff ff ff}  //weight: 1, accuracy: High
        $x_2_2 = "main.deleteShadowCopy" ascii //weight: 2
        $x_1_3 = "main.deleteDirs" ascii //weight: 1
        $x_1_4 = "main.generateRandomName" ascii //weight: 1
        $x_1_5 = "main.overwriteFilename" ascii //weight: 1
        $x_1_6 = "os.rename" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

