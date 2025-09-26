rule Trojan_Win64_YiBackdoor_YBI_2147953202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/YiBackdoor.YBI!MTB"
        threat_id = "2147953202"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "YiBackdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 0f 6f c8 66 0f fd cf 66 0f f9 cb 30 0c 3e 66 0f 6f d8 66 0f 6f cb 66 0f 6d fb}  //weight: 1, accuracy: High
        $x_1_2 = {66 0f 6f c3 66 0f 38 30 d0 66 0f 6d cf 66 0f 6c ca 66 0f 6f c3 66 0f 6f cb 66 0f 62 c2 66 0f 6a ca 66 0f f9 d8 66 0f f9 fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_YiBackdoor_YBJ_2147953203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/YiBackdoor.YBJ!MTB"
        threat_id = "2147953203"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "YiBackdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 4c 77 26 07 e8 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? b9 49 f7 02 78 e8 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? b9 58 a4 53 e5 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

