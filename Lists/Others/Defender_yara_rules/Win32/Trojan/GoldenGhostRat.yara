rule Trojan_Win32_GoldenGhostRat_AGR_2147973803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GoldenGhostRat.AGR!MTB"
        threat_id = "2147973803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GoldenGhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 85 24 ff ff ff c7 85 6c ff ff ff 52 65 67 53 c7 85 70 ff ff ff 65 74 56 61 c7 85 74 ff ff ff 6c 75 65 45 66 c7 85 78 ff ff ff 78 41 88 9d 7a ff ff ff 8d 85 6c ff ff ff 50 8d 45 d4 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

