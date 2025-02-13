rule Trojan_Win32_Petya_G_2147718806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Petya.G"
        threat_id = "2147718806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Petya"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 e6 3c 3d 35 03 e8 ?? ?? ?? ?? 81 f2 ae 51 f1 08 85 c0 70}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Petya_EB_2147839898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Petya.EB!MTB"
        threat_id = "2147839898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Petya"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files have been encrypted with strongest encryption algorithm and unique key" ascii //weight: 1
        $x_1_2 = "bcdedit /set {current} bootstatuspolicy IgnoreAllFailures" ascii //weight: 1
        $x_1_3 = "shutdown -r -t 1 -f g a t e . p h p ?" ascii //weight: 1
        $x_1_4 = "SetWindowsHookExW" ascii //weight: 1
        $x_1_5 = "j a s t e r . i n / n e w s /" ascii //weight: 1
        $x_1_6 = "Rumold Ransomware.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

