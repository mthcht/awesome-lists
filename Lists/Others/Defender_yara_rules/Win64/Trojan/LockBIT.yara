rule Trojan_Win64_LockBIT_ARAX_2147924337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LockBIT.ARAX!MTB"
        threat_id = "2147924337"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LockBIT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "del /s /f /q C:\\*.bak" ascii //weight: 2
        $x_2_2 = "del /s /f /q C:\\*.vhd" ascii //weight: 2
        $x_2_3 = "bcdedit /set {default} recoveryenabled No" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

