rule Ransom_Win64_PrinzEugen_MKV_2147972067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PrinzEugen.MKV!MTB"
        threat_id = "2147972067"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PrinzEugen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID: \"W4Q-Mnr-ahLuH3grQDNQ/" ascii //weight: 1
        $x_1_2 = "scorched-earth-ausfc/cmd/encrypter/main.go" ascii //weight: 1
        $x_1_3 = "main.encryptOne" ascii //weight: 1
        $x_1_4 = "main.selfDelete" ascii //weight: 1
        $x_1_5 = ".VerifyEncryptedWithKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

