rule Trojan_Win64_Turtleloader_AA_2147908010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Turtleloader.AA!MTB"
        threat_id = "2147908010"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Turtleloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c8 48 99 49 f7 fb 41 8a 04 12 41 32 04 09 88 04 0e 48 ff c1 48 81 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

