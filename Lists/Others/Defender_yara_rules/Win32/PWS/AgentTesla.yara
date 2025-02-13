rule PWS_Win32_AgentTesla_YA_2147732047_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/AgentTesla.YA!MTB"
        threat_id = "2147732047"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Password could not decrypted." wide //weight: 1
        $x_1_2 = "hostname|encryptedPassword|encryptedUsername" wide //weight: 1
        $x_1_3 = "Path=([A-z0-9\\/\\.]+)" wide //weight: 1
        $x_1_4 = "\\Thunderbird\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_AgentTesla_YB_2147734995_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/AgentTesla.YB!MTB"
        threat_id = "2147734995"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Debug\\IELibrary.pdb" ascii //weight: 1
        $x_1_2 = "$83018595-3f8a-4e71-94b2-8e41a61ed763" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

