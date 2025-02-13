rule Trojan_Win64_UACBypass_YTB_2147922270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UACBypass.YTB!MTB"
        threat_id = "2147922270"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UACBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:/Temp/firedrill-main/firedrill-main/cmd/uac_bypass/main.go" ascii //weight: 1
        $x_1_2 = "pkg/behaviours/bypass_fodhelper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

