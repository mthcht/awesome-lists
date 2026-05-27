rule Trojan_Win64_RemcosRAT_KAT_2147946557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RemcosRAT.KAT!MTB"
        threat_id = "2147946557"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 30 00 00 00 48 8b 50 60 48 85 c9 75 09 48 8b 42 10 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RemcosRAT_NA_2147970236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RemcosRAT.NA!MTB"
        threat_id = "2147970236"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "powershell" wide //weight: 5
        $x_1_2 = "h -enc" wide //weight: 1
        $x_2_3 = "Invoke-WebRequest" wide //weight: 2
        $x_5_4 = {24 00 65 00 6e 00 76 00 3a 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 [0-46] 2e 00 65 00 78 00 65 00}  //weight: 5, accuracy: Low
        $x_5_5 = {73 00 74 00 61 00 72 00 74 00 20 00 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 [0-46] 2e 00 62 00 61 00 74 00 20 00 2d 00 56 00 65 00 72 00 62 00 20 00 52 00 75 00 6e 00 41 00 73 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

