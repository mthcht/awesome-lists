rule Trojan_Win64_GoBitLoader_GV_2147920748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoBitLoader.GV!MTB"
        threat_id = "2147920748"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoBitLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "main.RedirectToPayload" ascii //weight: 3
        $x_3_2 = "main.HollowProcess" ascii //weight: 3
        $x_3_3 = "main.AesDecode.func1" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

