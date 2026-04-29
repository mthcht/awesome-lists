rule Trojan_Win64_ExamCheat_VGK_2147968013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ExamCheat.VGK!MTB"
        threat_id = "2147968013"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ExamCheat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 34 ff c0 89 44 24 34 48 63 44 24 34 0f be 44 04 60 85 c0 74 24 48 63 44 24 34 0f b6 44 04 60 8b 4c 24 30 33 c8 8b c1 89 44 24 30 69 44 24 30 [0-4] 89 44 24 30 eb c4}  //weight: 1, accuracy: Low
        $x_1_2 = "rmdir /s /q \"%sminhook" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

