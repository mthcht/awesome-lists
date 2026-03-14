rule Trojan_Win64_DisguisedMiner_AMX_2147964761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DisguisedMiner.AMX!MTB"
        threat_id = "2147964761"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DisguisedMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b 4b 38 48 85 c9 74 49 48 8b 01 ff 50 10 84 c0 75 24 48 83 c3 40 48 3b df 75 e4 48 8b 4e 40 48 8b 41 18 48 8b 50 28 80 7a 23 00}  //weight: 10, accuracy: High
        $x_1_2 = "Services and Controller app" wide //weight: 1
        $x_1_3 = "java.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

