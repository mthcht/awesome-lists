rule Trojan_Win64_ShellCode_MK_2147957334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCode.MK!MTB"
        threat_id = "2147957334"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {48 8b 45 10 0f b6 40 05 88 45 fb 48 8b 45 10 0f b6 40 04 88 45 fa 0f b6 45 fb c1 e0 ?? 89 c2 0f b6 45 fa 09 d0 66 89 45 fc 0f b7 45 fc}  //weight: 15, accuracy: Low
        $x_10_2 = {0f b7 55 fe b8 00 00 00 00 29 d0 c1 e0 ?? 48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 00 3c 4c}  //weight: 10, accuracy: Low
        $x_5_3 = "[+] Memory changed to PAGE_EXECUTE_READ" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

