rule Trojan_Win64_CobalStrike_ARAX_2147944891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobalStrike.ARAX!MTB"
        threat_id = "2147944891"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobalStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 32 ca 44 8b 54 24 30 41 ff c2 41 88 09 49 ff c1 44 89 54 24 30 4c 89 4c 24 28 41 8d 04 32 3b c3 0f 8c 79 fc ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

