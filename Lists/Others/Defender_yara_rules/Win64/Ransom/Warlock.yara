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

rule Ransom_Win64_Warlock_JKT_2147960776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Warlock.JKT!MTB"
        threat_id = "2147960776"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Warlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 c2 48 d3 ea 41 30 14 04 48 83 c0 ?? 48 83 f8 ?? 75 ?? 41 c6 44 24 ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c1 49 89 d3 83 e1 ?? 48 c1 e1 ?? 49 d3 eb 44 30 5c 05 ?? 48 83 c0 ?? 48 83 f8 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Warlock_JKU_2147960777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Warlock.JKU!MTB"
        threat_id = "2147960777"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Warlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VECT LOCKER" ascii //weight: 1
        $x_1_2 = "ENCRYPTING" ascii //weight: 1
        $x_1_3 = "Files Encrypted" ascii //weight: 1
        $x_1_4 = "All files successfully encrypted" ascii //weight: 1
        $x_1_5 = "ENCRYPTION COMPLETE" ascii //weight: 1
        $x_1_6 = "Check !!!_READ_ME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

