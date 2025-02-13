rule TrojanSpy_AndroidOS_SpinOK_A_2147848448_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpinOK.A!MTB"
        threat_id = "2147848448"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpinOK"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d3hdbjtb1686tn.cloudfront.net" ascii //weight: 1
        $x_1_2 = "Lcom/spin/ok/gp/receiver/SpinReceiver" ascii //weight: 1
        $x_1_3 = "/OkSpinProvider" ascii //weight: 1
        $x_1_4 = "/OksActivity" ascii //weight: 1
        $x_1_5 = "AES/GCM/NoPadding" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

