rule Ransom_Win64_BlackStriker_YBR_2147920122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackStriker.YBR!MTB"
        threat_id = "2147920122"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackStriker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LEIA-ME.txt" ascii //weight: 1
        $x_3_2 = "o, parece que seus arquivos INFELIZMENTE foram criptografados, bla bla" ascii //weight: 3
        $x_1_3 = "blawscriptFailed to execute self-deleting script" ascii //weight: 1
        $x_1_4 = "BlackStriker.pdb" ascii //weight: 1
        $x_1_5 = "library\\core\\src\\escape.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

