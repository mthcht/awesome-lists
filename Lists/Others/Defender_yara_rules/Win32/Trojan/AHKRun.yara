rule Trojan_Win32_AHKRun_GPF_2147905959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AHKRun.GPF!MTB"
        threat_id = "2147905959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AHKRun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StrReplace(value" ascii //weight: 1
        $x_1_2 = "RegExMatch(text" ascii //weight: 1
        $x_1_3 = "AntiVirusProduct" ascii //weight: 1
        $x_1_4 = "AntiSpywareProduct" ascii //weight: 1
        $x_1_5 = "root\\SecurityCenter2" ascii //weight: 1
        $x_1_6 = "A_AppData" ascii //weight: 1
        $x_1_7 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

