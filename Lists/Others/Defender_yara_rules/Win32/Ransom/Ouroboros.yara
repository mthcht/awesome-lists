rule Ransom_Win32_Ouroboros_GG_2147744467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ouroboros.GG!MTB"
        threat_id = "2147744467"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ouroboros"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 6d 00 6f 00 74 00 68 00 65 00 72 00 66 00 75 00 63 00 6b 00 65 00 72 00 5c 00 [0-15] 5c 00 6d 00 6f 00 74 00 68 00 65 00 72 00 66 00 75 00 63 00 6b 00 65 00 72 00 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 6d 6f 74 68 65 72 66 75 63 6b 65 72 5c [0-15] 5c 6d 6f 74 68 65 72 66 75 63 6b 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Ouroboros_PA_2147749658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ouroboros.PA!MTB"
        threat_id = "2147749658"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ouroboros"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all" ascii //weight: 1
        $x_1_2 = "Unlock-Files.txt" wide //weight: 1
        $x_1_3 = "netsh firewall set opmode mode=disable" ascii //weight: 1
        $x_1_4 = "All Your Files Has Been Encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

