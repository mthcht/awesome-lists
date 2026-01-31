rule Ransom_Win64_Milkyway_YBG_2147962107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Milkyway.YBG!MTB"
        threat_id = "2147962107"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Milkyway"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\lock.png" ascii //weight: 1
        $x_1_2 = "INCORRECT DECRYPTION KEY" ascii //weight: 1
        $x_1_3 = "README.txt" ascii //weight: 1
        $x_1_4 = "MilkywayMutex" ascii //weight: 1
        $x_1_5 = "encrypted your infrastructure" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

