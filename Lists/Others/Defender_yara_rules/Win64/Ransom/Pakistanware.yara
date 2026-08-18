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

