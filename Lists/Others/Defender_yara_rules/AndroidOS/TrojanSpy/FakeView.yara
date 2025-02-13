rule TrojanSpy_AndroidOS_FakeView_DS_2147809143_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeView.DS!MTB"
        threat_id = "2147809143"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeView"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mobilespy" ascii //weight: 1
        $x_1_2 = "NO SMS $$$$$$$$$$$$$$$$$" ascii //weight: 1
        $x_1_3 = "Checking for Outgoing SMS" ascii //weight: 1
        $x_1_4 = "spy_db" ascii //weight: 1
        $x_1_5 = "cellphonerecon.com" ascii //weight: 1
        $x_1_6 = "ContactUploader" ascii //weight: 1
        $x_1_7 = "CallSpy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

