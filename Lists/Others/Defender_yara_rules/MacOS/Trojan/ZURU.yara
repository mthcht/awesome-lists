rule Trojan_MacOS_ZuRu_A_2147795254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/ZuRu.A!MTB"
        threat_id = "2147795254"
        type = "Trojan"
        platform = "MacOS: "
        family = "ZuRu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hookCommon" ascii //weight: 1
        $x_1_2 = "myOCLog" ascii //weight: 1
        $x_1_3 = "SSLPinningMode" ascii //weight: 1
        $x_1_4 = "runShellWithCommand:completeBlock" ascii //weight: 1
        $x_1_5 = ".cxx_destruct" ascii //weight: 1
        $x_1_6 = "/compiler-rt/lib/builtins/os_version_check.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

