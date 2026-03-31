rule Trojan_MSIL_FBStealer_SX_2147965917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FBStealer.SX!MTB"
        threat_id = "2147965917"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FBStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "VNLIKE247.NET.Properties.Resources" ascii //weight: 30
        $x_10_2 = "\\\\\"qeid\\\\\":\\\\\"(\\d+)\\\\\"" ascii //weight: 10
        $x_10_3 = "logout_hash\":\"(.*?)\"" ascii //weight: 10
        $x_5_4 = "copydongboiden" ascii //weight: 5
        $x_5_5 = "credentials2.json" ascii //weight: 5
        $x_1_6 = "www.facebook.com/login" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

