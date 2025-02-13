rule Trojan_MacOS_Sliver_D_2147825781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Sliver.D!MTB"
        threat_id = "2147825781"
        type = "Trojan"
        platform = "MacOS: "
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sliverpb.Shell" ascii //weight: 1
        $x_1_2 = "sliverpb.BackdoorReq" ascii //weight: 1
        $x_1_3 = "sliverpb.ProcessDumpReq" ascii //weight: 1
        $x_1_4 = "github.com/bishopfox/sliver/implant/sliver/" ascii //weight: 1
        $x_1_5 = "ScreenshotReq" ascii //weight: 1
        $x_1_6 = "bishopfox/sliver/protobuf/sliverpbb." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MacOS_Sliver_E_2147831570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Sliver.E!MTB"
        threat_id = "2147831570"
        type = "Trojan"
        platform = "MacOS: "
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bishopfox/sliver/protobuf/sliverpbb" ascii //weight: 1
        $x_1_2 = "sliverpb.PivotListener" ascii //weight: 1
        $x_1_3 = "ScreenshotReq" ascii //weight: 1
        $x_1_4 = "SSHCommandReq" ascii //weight: 1
        $x_1_5 = "BackdoorReq" ascii //weight: 1
        $x_1_6 = "sliverpb.RegisterR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

