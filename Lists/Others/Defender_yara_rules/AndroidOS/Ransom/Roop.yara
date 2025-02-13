rule Ransom_AndroidOS_Roop_A_2147783352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Roop.A!MTB"
        threat_id = "2147783352"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Roop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You device will be unprotectable. Are you sure?" ascii //weight: 1
        $x_1_2 = "LockActivity" ascii //weight: 1
        $x_1_3 = "activityClearHistory" ascii //weight: 1
        $x_1_4 = "enableLockAsHomeLauncher" ascii //weight: 1
        $x_1_5 = "shouldLockScreen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

