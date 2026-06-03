rule TrojanDropper_Win64_XMRig_CM_2147963892_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/XMRig.CM!MTB"
        threat_id = "2147963892"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "echo File deleted successfully." ascii //weight: 2
        $x_2_2 = "del \"%~f0\"" ascii //weight: 2
        $x_2_3 = "delete_self.bat" ascii //weight: 2
        $x_2_4 = "/q /c start %windir%\\explorer _ & _\\explorer.exe" wide //weight: 2
        $x_2_5 = "kernel32 .dll" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win64_XMRig_AHA_2147970737_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/XMRig.AHA!MTB"
        threat_id = "2147970737"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "mK9xP2Qv8Rz7Ht4Nc1BwY5Lf3Ds6Aj0Xe9GpVu2Ti7ZnCm8Rq4HyKd1Sb5OwEf6U" ascii //weight: 30
        $x_20_2 = "%s\\Zhujikdo" ascii //weight: 20
        $x_10_3 = "%s\\Temp\\Job_Infomation.pdf" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win64_XMRig_AH_2147970793_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/XMRig.AH!MTB"
        threat_id = "2147970793"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {40 0f b6 c7 41 0f b6 14 06 43 32 14 18 49 ff c0 88 14 3b 4d 3b c2 72}  //weight: 30, accuracy: High
        $x_20_2 = "$Proxy for msvcr100_clr" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

