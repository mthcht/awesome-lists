rule Trojan_Win64_QakbotPacker_QM_2147903208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QakbotPacker.QM!MTB"
        threat_id = "2147903208"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QakbotPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f5 d7 39 07 d7 e7 ?? 03 35 ?? ?? ?? ?? 98 35 ?? ?? ?? ?? e0 ?? ff 07 d7 4a 33 98 ?? ?? ?? ?? 6a ?? 75 ?? f5 1a d7 e4 ?? 6a 0f 75 ?? f5 2b 73 ?? f5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

