rule Trojan_Win32_SuspSchTask_ZK_2147968838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSchTask.ZK!MTB"
        threat_id = "2147968838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSchTask"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "schtasks.exe" wide //weight: 1
        $x_1_2 = "/create /tn" wide //weight: 1
        $x_1_3 = "MicrosoftEdgeUpdateSvc" wide //weight: 1
        $x_1_4 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 72 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 [0-60] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "/sc onlogon" wide //weight: 1
        $x_1_6 = "highest" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

