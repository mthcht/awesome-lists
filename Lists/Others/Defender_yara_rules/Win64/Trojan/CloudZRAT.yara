rule Trojan_Win64_CloudZRAT_DD_2147968573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CloudZRAT.DD!MTB"
        threat_id = "2147968573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CloudZRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$_.Name -ieq 'regasm.exe' -and $_.CommandLine -match" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\Microsoft\\WindowsDoc\\" ascii //weight: 1
        $x_1_3 = "schtasks /run /tn" ascii //weight: 1
        $x_1_4 = "/sc onlogon /ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CloudZRAT_DF_2147968574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CloudZRAT.DF!MTB"
        threat_id = "2147968574"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CloudZRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$b2257e41-9b69-4dc3-9433-b5e949090d01" ascii //weight: 10
        $x_1_2 = "ConfuserEx" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "Convert" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

