rule Trojan_Win64_VampireBot_AVB_2147955411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VampireBot.AVB!MTB"
        threat_id = "2147955411"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VampireBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 34 11 89 f7 40 c0 ee 04 40 0f b6 f6 4c 8d 05 4e c3 21 00 42 0f b6 34 06 48 83 fb 20 0f 83 3d ?? ?? ?? 40 88 34 18 48 8d 73 01 83 e7 0f 42 0f b6 3c 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

