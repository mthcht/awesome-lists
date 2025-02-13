rule Ransom_AndroidOS_Small_A_2147783353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Small.A!MTB"
        threat_id = "2147783353"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "To continue, you must activate the application. Click to activate" ascii //weight: 1
        $x_1_2 = "force-locked" ascii //weight: 1
        $x_1_3 = "com.example.testlock" ascii //weight: 1
        $x_1_4 = "May lose user data. Do you want to continue" ascii //weight: 1
        $x_1_5 = "wasScreenOn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

