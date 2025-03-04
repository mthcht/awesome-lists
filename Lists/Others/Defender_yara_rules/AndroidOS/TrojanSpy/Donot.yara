rule TrojanSpy_AndroidOS_Donot_YA_2147756438_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Donot.YA!MTB"
        threat_id = "2147756438"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Donot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dcteat$a.run()" ascii //weight: 1
        $x_1_2 = "RUhFSEZJUkdCVkZGRFNB" ascii //weight: 1
        $x_1_3 = "RUhFSEZJVUVJRkVGRFNB" ascii //weight: 1
        $x_1_4 = "WappHolder.txt" ascii //weight: 1
        $x_1_5 = "keys.txt" ascii //weight: 1
        $x_1_6 = "CallLogs.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

