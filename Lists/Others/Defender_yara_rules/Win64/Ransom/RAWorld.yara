rule Ransom_Win64_RAWorld_YAF_2147945543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/RAWorld.YAF!MTB"
        threat_id = "2147945543"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "RAWorld"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RA World" ascii //weight: 1
        $x_1_2 = "data are stolen and encrypted" ascii //weight: 1
        $x_1_3 = "don't pay" ascii //weight: 1
        $x_1_4 = "release the data" ascii //weight: 1
        $x_1_5 = "decrypt some files" ascii //weight: 1
        $x_1_6 = "decryption tool " ascii //weight: 1
        $x_1_7 = "the higher ransom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

