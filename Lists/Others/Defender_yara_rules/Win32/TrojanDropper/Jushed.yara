rule TrojanDropper_Win32_Jushed_AS_2147751933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Jushed.AS!MTB"
        threat_id = "2147751933"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Jushed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 17 83 c7 04 ba ?? ?? ?? ?? 8b 01 03 d0 83 f0 ?? 33 c2 8b 11 83 c1 04 a9}  //weight: 1, accuracy: Low
        $x_1_2 = "jusched.exe" ascii //weight: 1
        $x_1_3 = "WoitAtdDcyenserGiwro" ascii //weight: 1
        $x_1_4 = "VmfantunmoelIriGoeotA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

