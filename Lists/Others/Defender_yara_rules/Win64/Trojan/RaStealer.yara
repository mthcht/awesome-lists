rule Trojan_Win64_RaStealer_PAE_2147839484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RaStealer.PAE!MTB"
        threat_id = "2147839484"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 2b c2 48 83 f8 02 72 ?? 80 f9 0d 75 ?? ?? ?? ?? ?? ?? 0a 74 ?? 80 f9 0a 74 [0-4] 0f 85 ?? ?? ?? ?? 80 f9 3d 75 [0-10] 0f 87 ?? ?? ?? ?? 80 f9 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 80 f9 40 0f 94 c0 83 e1 3f 49 [0-3] 44 2b ?? 41 8b ?? 44 8b ?? c1 e0 06 44 0b ?? 49 83 fb 04 75 ?? 45 33 db 45 85 ?? 74 ?? 41 8b ?? c1 e8 10 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

