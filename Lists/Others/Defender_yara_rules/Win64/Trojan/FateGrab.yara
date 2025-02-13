rule Trojan_Win64_FateGrab_FG_2147848040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FateGrab.FG!MTB"
        threat_id = "2147848040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FateGrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 0c 0a 33 c1 b9 01 00 00 00 48 6b c9 07 48 8b 54 24 08 0f b6 0c 0a 33 c1 33 44 24 10}  //weight: 1, accuracy: High
        $x_1_2 = "MimeSource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FateGrab_JM_2147848517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FateGrab.JM!MTB"
        threat_id = "2147848517"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FateGrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 8d 4f 03 45 32 0e 41 80 f1 09 48 3b ca 73 23 48 8d 41 01 48 89 44 24 40 48 8d 44 24 30 48 83 fa 10 48 0f 43 44 24 30 44 88 0c 08 c6 44 08 01 00}  //weight: 5, accuracy: High
        $x_1_2 = "MsStartup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

