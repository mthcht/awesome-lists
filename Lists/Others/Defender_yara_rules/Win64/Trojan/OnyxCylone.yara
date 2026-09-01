rule Trojan_Win64_OnyxCylone_YAB_2147977327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OnyxCylone.YAB!MTB"
        threat_id = "2147977327"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OnyxCylone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Onyx 2.0 Loader @ 2020 All rights reserved" ascii //weight: 2
        $x_1_2 = "RUST INTERNAL" ascii //weight: 1
        $x_5_3 = "RUST EXTERNAL" ascii //weight: 5
        $x_10_4 = "example_win32_directx11.pdb" ascii //weight: 10
        $x_1_5 = "Insert your key here" ascii //weight: 1
        $x_1_6 = "Are you having a problem with your injector?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

