rule Trojan_Win64_Lazarus_A_2147769063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazarus.A!ibt"
        threat_id = "2147769063"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazarus"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curred while reading from the client: %d" wide //weight: 1
        $x_1_2 = "Receive Update command from trojan" wide //weight: 1
        $x_1_3 = "Receive disconnect command from trojan" wide //weight: 1
        $x_1_4 = "Receive Uninstall command from Trojan" wide //weight: 1
        $x_1_5 = "destination_address_required" ascii //weight: 1
        $x_1_6 = "ExeRelease\\maintenanceservice_x64_ExeRelease.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win64_Lazarus_MCP_2147959051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazarus.MCP!MTB"
        threat_id = "2147959051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazarus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6c 69 76 65 72 43 75 73 74 6f 6d [0-18] 44 4c 4c 2e 64 6c 6c 00 6d 61 69 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 6d 73 76 63 6a 6d 63 [0-32] c0 2e 30 30 63 66 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

