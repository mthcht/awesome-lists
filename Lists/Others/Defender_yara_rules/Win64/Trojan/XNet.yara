rule Trojan_Win64_XNet_GVM_2147971220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XNet.GVM!MTB"
        threat_id = "2147971220"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XNet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 c3 33 c9 4c 8d 14 82 4d 8d 0c 80 ?? ?? 41 0f b6 84 0a ?? ?? ?? ?? 41 30 04 09 48 ff c1 48 83 f9 04 75 ea 41 fe c3 44 3a d9 72 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

