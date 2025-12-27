rule TrojanDownloader_Linux_TransparentTribe_A_2147959450_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Linux/TransparentTribe.A!MTB"
        threat_id = "2147959450"
        type = "TrojanDownloader"
        platform = "Linux: Linux platform"
        family = "TransparentTribe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.(*___ClientStruct).___InstallPersistenceFeatures" ascii //weight: 2
        $x_2_2 = "main.(*___ClientStruct).___ProcessUploadAndExecute" ascii //weight: 2
        $x_2_3 = "main.(*___ClientStruct).___ObtainExternalIP" ascii //weight: 2
        $x_2_4 = "main.(*___ClientStruct).___AddToCrontabScheduler" ascii //weight: 2
        $x_2_5 = "main.(*___ClientStruct).___RunInStealthMode" ascii //weight: 2
        $x_1_6 = "main.(*___ClientStruct).___AttemptLocationRetrieval" ascii //weight: 1
        $x_1_7 = "main.___evasion_transform_string" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

