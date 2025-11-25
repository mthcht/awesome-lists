rule Ransom_Win64_Warlock_SW_2147958204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Warlock.SW!MTB"
        threat_id = "2147958204"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Warlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Warlock Group" ascii //weight: 1
        $x_1_2 = "Armadillo_Mutex" ascii //weight: 1
        $x_1_3 = "a professional hack organization" ascii //weight: 1
        $x_1_4 = "Your systems have been locked using our advanced encryption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

