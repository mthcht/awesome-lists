rule Backdoor_Win64_Stowaway_GVA_2147954382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Stowaway.GVA!MTB"
        threat_id = "2147954382"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Stowaway"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[*]All rules have been cleared successfully!" ascii //weight: 1
        $x_1_2 = "\\n[*]Downloading file,please wait......" ascii //weight: 1
        $x_1_3 = "[*]Admin seems still down" ascii //weight: 1
        $x_5_4 = "Stowaway" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

