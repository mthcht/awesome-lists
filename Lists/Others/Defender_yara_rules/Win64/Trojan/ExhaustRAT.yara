rule Trojan_Win64_ExhaustRAT_AB_2147921617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ExhaustRAT.AB!MTB"
        threat_id = "2147921617"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ExhaustRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Exhaust-RAT" ascii //weight: 1
        $x_1_2 = "HKLM\\Software\\Classes\\Folder\\shell\\sandbox" ascii //weight: 1
        $x_1_3 = "GetComputerNameExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

