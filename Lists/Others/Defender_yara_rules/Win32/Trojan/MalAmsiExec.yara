rule Trojan_Win32_MalAmsiExec_A_2147947101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalAmsiExec.A!MTB"
        threat_id = "2147947101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalAmsiExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[text.encoding]::UTF8.getstring($" wide //weight: 1
        $x_1_2 = "[convert]::frombase64string($" wide //weight: 1
        $x_1_3 = "COMSPEC" wide //weight: 1
        $x_1_4 = "ECHO" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MalAmsiExec_A_2147947101_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalAmsiExec.A!MTB"
        threat_id = "2147947101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalAmsiExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[text.encoding]::UTF8.getstring($" wide //weight: 1
        $x_1_2 = "[convert]::frombase64string($" wide //weight: 1
        $x_1_3 = "COMSPEC" wide //weight: 1
        $x_1_4 = "ECHO" wide //weight: 1
        $x_1_5 = ";nal x ($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

