rule Ransom_Win64_Pakistanware_ABPK_2147976377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Pakistanware.ABPK!MTB"
        threat_id = "2147976377"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Pakistanware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Global\\WindowsSecurityHealthServiceMutexP" ascii //weight: 1
        $x_1_2 = "RECOVERY_README.txt" ascii //weight: 1
        $x_1_3 = "Your files encrypted by pakistanware" ascii //weight: 1
        $x_1_4 = "[geo] analysis environment detected" ascii //weight: 1
        $x_1_5 = "Click here to view contents.exe" ascii //weight: 1
        $x_1_6 = "TEMP\\pakistanware_flag.png" ascii //weight: 1
        $x_1_7 = "[done] encrypted=" ascii //weight: 1
        $x_1_8 = "/etc/shadowSOFTWARE\\Oracle\\VirtualBox Guest AdditionsSOFTWARE\\VMware, Inc.\\VMware Tools" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Pakistanware_ABSK_2147976775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Pakistanware.ABSK!MTB"
        threat_id = "2147976775"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Pakistanware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "X-Campaign: pakistanware-APT36" ascii //weight: 3
        $x_3_2 = "Your files encrypted by pakistanware" ascii //weight: 3
        $x_1_3 = "pakistanware/INSTRUCTIONS.txt" ascii //weight: 1
        $x_1_4 = "pakistanware/README.txt" ascii //weight: 1
        $x_1_5 = "APT36/NOTE.txt" ascii //weight: 1
        $x_2_6 = "[geo] analysis environment detected" ascii //weight: 2
        $x_2_7 = "/etc/shadowSOFTWARE\\Oracle\\VirtualBox Guest AdditionsSOFTWARE\\VMware, Inc.\\VMware Tools" ascii //weight: 2
        $x_1_8 = "TransparentTribe-health.exe" ascii //weight: 1
        $x_1_9 = "pakistanware-viewer.exe" ascii //weight: 1
        $x_1_10 = "APT36-decrypt.exe" ascii //weight: 1
        $x_1_11 = "pakistan-flag.exe" ascii //weight: 1
        $x_1_12 = "Click here to view contents.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

