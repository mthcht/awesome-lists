rule Trojan_Win64_XWormRAT_A_2147891366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWormRAT.A!MTB"
        threat_id = "2147891366"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "go-runpe" ascii //weight: 2
        $x_2_2 = "cipher.NewCFBDecrypter" ascii //weight: 2
        $x_2_3 = "ioutil.TempDir" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_XWormRAT_B_2147898584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XWormRAT.B!MTB"
        threat_id = "2147898584"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XWormRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 0f b6 44 0a 22 41 c1 e0 10 44 0f b7 4c 0a 20 45 01 c8 41 81 c0 00 00 00 84 44 33 84 10 ?? ?? ?? ?? 44 89 44 14 50 48 83 c2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

