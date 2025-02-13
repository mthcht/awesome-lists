rule Ransom_Win64_SuchCrypt_PA_2147756926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SuchCrypt.PA!MTB"
        threat_id = "2147756926"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SuchCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Go build ID: \"GerjxNEfy4gHBYpB64v2/joNTalGJe9U8Yg6dfPy2/umrIDSyjS4lMeiC6xWjV/KsxLmA7v9NoUmVBtr-4E\"" ascii //weight: 10
        $x_10_2 = "at  fp= is  lr: of  on  pc= sp: sp=" ascii //weight: 10
        $x_10_3 = "size = .mwahahah244140625" ascii //weight: 10
        $x_1_4 = "decrypt" ascii //weight: 1
        $x_1_5 = "encrypt" ascii //weight: 1
        $x_1_6 = "createtoolhelp32snapshot" ascii //weight: 1
        $x_1_7 = "such-crypt/main.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

