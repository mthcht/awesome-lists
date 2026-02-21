rule Ransom_Win64_HujEncrypt_YBG_2147963480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HujEncrypt.YBG!MTB"
        threat_id = "2147963480"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HujEncrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {45 02 c0 32 ca 41 32 c0 41 32 c3 88 4e 05 0f b6 56 09 41 32 c1 44 0f b6 4e 0a 88 46 06 0f b6 c3}  //weight: 4, accuracy: High
        $x_1_2 = "huj_encrypt.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

