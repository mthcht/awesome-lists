rule Trojan_Win64_ShellcoderRunner_HHN_2147959718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcoderRunner.HHN!MTB"
        threat_id = "2147959718"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcoderRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ff c8 83 c8 e0 ff c0 48 98 ff c1 42 0f b6 04 00 30 02 48 ff c2 48 63 c1 48 3b c7 72 d9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

