rule Trojan_Win64_BlisterLoader_SA_2147902118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlisterLoader.SA!MTB"
        threat_id = "2147902118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlisterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c0 4d 8d 49 ?? 41 33 c0 44 69 c0 ?? ?? ?? ?? 41 8b c0 c1 e8 ?? 44 33 c0 41 ?? ?? ?? 66 ?? ?? 75 ?? 41 ?? ?? ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be c0 49 03 cc 41 33 c1 44 ?? ?? ?? ?? ?? ?? 41 8b c1 c1 e8 ?? 44 33 c8 8a 01 84 c0 75 ?? 41 ?? ?? ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

