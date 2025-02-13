rule Trojan_Win64_RevShellz_A_2147922092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RevShellz.A!MTB"
        threat_id = "2147922092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RevShellz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 06 4e 0f be ac 20 60 39 24 00 41 8d 4d 01 4c 8b 4d 9f 4c 2b ce 48 63 c1 49 3b c1 ?? ?? ?? ?? ?? ?? 48 89 7d af 48 89 75 df 8b c7 83 f9 04 0f 94 c0 ff c0 44 8b f0 44 8b c0 4c 89 54 24 20}  //weight: 1, accuracy: Low
        $x_1_2 = "payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

