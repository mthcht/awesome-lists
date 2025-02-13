rule Trojan_Win32_VTFlooder_BYF_2147827188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VTFlooder.BYF!MTB"
        threat_id = "2147827188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VTFlooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a6281279.yolox.net" ascii //weight: 1
        $x_1_2 = "VMGrab" ascii //weight: 1
        $x_1_3 = "/vtapi/v2/file/scan" ascii //weight: 1
        $x_1_4 = "4d1ee14a3191ba1afde5261326dcd7e81793afacb6aa7e46d0b467bc6ebcd367" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

