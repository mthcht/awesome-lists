rule Trojan_Win64_RootKit_LK_2147851153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RootKit.LK!MTB"
        threat_id = "2147851153"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RootKit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\nullout.pdb" ascii //weight: 1
        $x_1_2 = "Safengine Shielden v2" ascii //weight: 1
        $x_1_3 = "SESDKDummy64.dll" ascii //weight: 1
        $x_1_4 = "SEProtectStartMutation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

