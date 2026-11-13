rule Trojan_Win64_LodeInfo_GV_2147981992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LodeInfo.GV!MTB"
        threat_id = "2147981992"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LodeInfo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 2b e0 48 8b 05 1e 9d 12 00 48 33 c4 48 89 44 24 40 48 8d 05 07 6b 14 00 48 89 44 24 20 48 8b 44 24 20 0f b6 08 80 f9 3f 75 54}  //weight: 1, accuracy: High
        $x_1_2 = "2642052c2eab8a76adcccdf90f2c194922b8cc56" ascii //weight: 1
        $x_1_3 = "SPIFdor__atarats" ascii //weight: 1
        $x_1_4 = "etaonrishdlcupfm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

