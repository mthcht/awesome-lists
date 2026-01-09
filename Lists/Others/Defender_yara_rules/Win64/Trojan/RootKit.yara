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

rule Trojan_Win64_RootKit_MK_2147960851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RootKit.MK!MTB"
        threat_id = "2147960851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RootKit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {fd 05 c3 5d d6 97 cd a4 86 ac fa b2 5d 8e ac f3}  //weight: 15, accuracy: High
        $x_15_2 = {ad 68 1d 28 43 48 15 18 d0 79 77 07 cb 23 55}  //weight: 15, accuracy: High
        $x_15_3 = {b5 32 9a 3a 97 4b 7b 57 13 71 ef 6a fc 60 93 6c}  //weight: 15, accuracy: High
        $x_10_4 = {2e 64 61 74 61 00 00 00 b8 81 01 00 00 10 01}  //weight: 10, accuracy: High
        $x_3_5 = {f8 2f 00 40 2a 00 00 00 70 50 00 c0}  //weight: 3, accuracy: High
        $x_2_6 = {0b 02 0e 1d 00 fa 00 00 00 a8 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

