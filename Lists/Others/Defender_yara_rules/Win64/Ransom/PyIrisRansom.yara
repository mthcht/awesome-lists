rule Ransom_Win64_PyIrisRansom_YAB_2147922275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PyIrisRansom.YAB!MTB"
        threat_id = "2147922275"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PyIrisRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "IRIS RANSOMWARE GROUP" ascii //weight: 10
        $x_1_2 = "attempt to restart, shut down" ascii //weight: 1
        $x_1_3 = "completely locked down" ascii //weight: 1
        $x_1_4 = "complete access to EVERYTHING" ascii //weight: 1
        $x_1_5 = "privacy no longer exists" ascii //weight: 1
        $x_1_6 = "files will be permanently destroyed" ascii //weight: 1
        $x_1_7 = "no way to recover them" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

