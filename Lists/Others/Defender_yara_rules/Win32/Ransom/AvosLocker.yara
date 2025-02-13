rule Ransom_Win32_AvosLocker_PAC_2147794682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/AvosLocker.PAC!MTB"
        threat_id = "2147794682"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "AvosLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your documents will be corrupted if a shutdown occurs during the encryption process." ascii //weight: 1
        $x_1_2 = "Zavos avoslinux avos" ascii //weight: 1
        $x_1_3 = "Bruteforce SMB" ascii //weight: 1
        $x_1_4 = "disabledrives" ascii //weight: 1
        $x_1_5 = "Disable mutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_AvosLocker_AB_2147794821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/AvosLocker.AB!MTB"
        threat_id = "2147794821"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "AvosLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 07 73 ?? 8a 84 0d ?? ?? ?? ?? 32 c2 88 85 ?? ?? ?? ?? 88 84 0d ?? ?? ?? ?? 41 89 8d ?? ?? ?? ?? 8a 95 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = "Bruteforce SMB for logical drives" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

