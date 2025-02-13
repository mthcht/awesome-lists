rule Trojan_Win32_Rastreio_RPX_2147846736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rastreio.RPX!MTB"
        threat_id = "2147846736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rastreio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QGVjaG8gb2ZmDQpzZXRsb2NhbCBFbmFibGVEZWxheWVkRXhwYW5zaW9uDQpj" wide //weight: 1
        $x_1_2 = "unknowndll.pdb" ascii //weight: 1
        $x_1_3 = "@echo off" ascii //weight: 1
        $x_1_4 = "setlocal EnableDelayedExpansion" ascii //weight: 1
        $x_1_5 = "%ls=%ls" ascii //weight: 1
        $x_1_6 = "[Rename]" ascii //weight: 1
        $x_1_7 = "ExecShell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rastreio_RPY_2147846745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rastreio.RPY!MTB"
        threat_id = "2147846745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rastreio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QGVjaG8gb2ZmDQpzZXRsb2NhbCBFbmFibGVEZWxheWVkRXhwYW5zaW9uDQpj" wide //weight: 1
        $x_1_2 = "unknowndll.pdb" ascii //weight: 1
        $x_1_3 = ".bat" wide //weight: 1
        $x_1_4 = "UnimplementedAPI" ascii //weight: 1
        $x_1_5 = "DllCanUnloadNow" ascii //weight: 1
        $x_1_6 = "%ls=%ls" ascii //weight: 1
        $x_1_7 = "[Rename]" ascii //weight: 1
        $x_1_8 = "ExecShell:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rastreio_RPZ_2147846746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rastreio.RPZ!MTB"
        threat_id = "2147846746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rastreio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@echo off" ascii //weight: 1
        $x_1_2 = "setlocal EnableDelayedExpansion" ascii //weight: 1
        $x_1_3 = {5e 53 5e 65 5e 74 20 [0-2] 3d 5e 53 5e 65 5e 74}  //weight: 1, accuracy: Low
        $x_1_4 = ".bat" wide //weight: 1
        $x_1_5 = "-wi 1 -" ascii //weight: 1
        $x_1_6 = "write-host $env:" ascii //weight: 1
        $x_1_7 = "del \"%~f0\"" ascii //weight: 1
        $x_10_8 = "!://!" ascii //weight: 10
        $x_10_9 = "!/^\",^\"!" ascii //weight: 10
        $x_10_10 = "!^\") ^| .($!" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

