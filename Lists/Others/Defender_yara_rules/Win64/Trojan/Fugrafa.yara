rule Trojan_Win64_Fugrafa_ARR_2147959951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fugrafa.ARR!MTB"
        threat_id = "2147959951"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fugrafa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_12_1 = {0f b6 0c 38 32 4c 04 20 88 0c 18 ff c0 41 3b c0 72}  //weight: 12, accuracy: High
        $x_8_2 = {44 33 cf 41 c1 c9 ?? 44 33 c5 41 c1 c8 ?? 47 8d 2c 0b 45 33 ea 41 c1 cd ?? 41 03 cd 41}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

