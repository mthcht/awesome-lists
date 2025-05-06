rule Trojan_MSIL_AntiVM_GTB_2147938919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AntiVM.GTB!MTB"
        threat_id = "2147938919"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AntiVM"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PowerShell" ascii //weight: 2
        $x_2_2 = "Malware" ascii //weight: 2
        $x_2_3 = "SELECT * FROM Win32_MappedLogicalDisk" ascii //weight: 2
        $x_2_4 = "SELECT * FROM Win32_UserProfile" ascii //weight: 2
        $x_1_5 = "vSphere" ascii //weight: 1
        $x_1_6 = "VMware" ascii //weight: 1
        $x_1_7 = "DiskChek" ascii //weight: 1
        $x_1_8 = "SavedRdpSessions.csv" ascii //weight: 1
        $x_1_9 = "get_ComputerName" ascii //weight: 1
        $x_1_10 = "get_UserName" ascii //weight: 1
        $x_1_11 = "InvokeMethod" ascii //weight: 1
        $x_1_12 = "Antivirus" ascii //weight: 1
        $x_1_13 = "BitDefender" ascii //weight: 1
        $x_1_14 = "Kaspersky" ascii //weight: 1
        $x_1_15 = "Norton" ascii //weight: 1
        $x_1_16 = "Avast" ascii //weight: 1
        $x_1_17 = "WebRoo" ascii //weight: 1
        $x_1_18 = "ESET" ascii //weight: 1
        $x_1_19 = "Defender" ascii //weight: 1
        $x_1_20 = "Sophos" ascii //weight: 1
        $x_1_21 = "Trend" ascii //weight: 1
        $x_1_22 = "Symantec Endpoint Protection" ascii //weight: 1
        $x_1_23 = "CrowdStrike" ascii //weight: 1
        $x_1_24 = "Cortex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AntiVM_SWA_2147940760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AntiVM.SWA!MTB"
        threat_id = "2147940760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AntiVM"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 07 25 4b 11 0e 11 11 1f 0f 5f 95 61 54 11 0e 11 11 1f 0f 5f 11 0e 11 11 1f 0f 5f 95 11 07 25 1a 58 13 07 4b 61 20 19 28 bb 3d 58 9e 11 11 17 58 13 11 00 11 20 17 58 13 20 11 20 11 08 fe 05 13 21 11 21 2d b9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

