rule Ransom_Win32_AnteFrigus_2147750284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/AnteFrigus!MSR"
        threat_id = "2147750284"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "AnteFrigus"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypted-not-wall\\Release\\encrypted-not-wall.pdb" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_3 = "To decrypt files follow the instructions below:" ascii //weight: 1
        $x_1_4 = "news.html" ascii //weight: 1
        $x_1_5 = "Your files on this computer have been encrypted due to security issues" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_AnteFrigus_SK_2147759305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/AnteFrigus.SK!MTB"
        threat_id = "2147759305"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "AnteFrigus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All these actions will lead to data loss and unrecoverable." ascii //weight: 1
        $x_1_2 = "Your files on this computer have been encrypted due to security issues." ascii //weight: 1
        $x_1_3 = "To decrypt files follow the instructions below:" ascii //weight: 1
        $x_5_4 = "wmic.exe shadowcopy delete" ascii //weight: 5
        $x_5_5 = "- personal key:" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

