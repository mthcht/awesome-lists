rule Trojan_Win64_Gogents_CA_2147970033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gogents.CA!MTB"
        threat_id = "2147970033"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gogents"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 08 48 c7 40 ?? ?? 00 00 00 48 8d 0d ?? ?? ?? ?? 48 89 48 ?? bb 02 00 00 00 48 89 d9 66 90 e8}  //weight: 10, accuracy: Low
        $x_2_2 = "KillProcessesWithExecutablePath" ascii //weight: 2
        $x_2_3 = "SelfInstall" ascii //weight: 2
        $x_2_4 = "decodeServerURLs" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

