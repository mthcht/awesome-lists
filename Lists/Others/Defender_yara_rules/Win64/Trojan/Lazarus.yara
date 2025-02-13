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

