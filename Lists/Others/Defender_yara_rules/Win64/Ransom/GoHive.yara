rule Ransom_Win64_GoHive_PAA_2147786531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GoHive.PAA!MTB"
        threat_id = "2147786531"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GoHive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "To decrypt all the data or to prevent it from leakage at our website" ascii //weight: 1
        $x_1_2 = "Follow the guidelines below to avoid losing your data:" ascii //weight: 1
        $x_1_3 = "Your sensitive data will be publicly disclosed" ascii //weight: 1
        $x_1_4 = "Do not try to decrypt data" ascii //weight: 1
        $x_1_5 = "Do not fool yourself." ascii //weight: 1
        $x_1_6 = "You will lose them." ascii //weight: 1
        $x_1_7 = "and in mass media" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

