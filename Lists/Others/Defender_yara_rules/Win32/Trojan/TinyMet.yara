rule Trojan_Win32_TinyMet_2147757889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TinyMet!ibt"
        threat_id = "2147757889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TinyMet"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tinymet.com" ascii //weight: 1
        $x_1_2 = "tinymet.exe 2 host.com 443" ascii //weight: 1
        $x_1_3 = "Usage: tinymet.exe [transport] LHOST LPORT" ascii //weight: 1
        $x_1_4 = "like TRANSPORT_LHOST_LPORT.exe" ascii //weight: 1
        $x_1_5 = "will use reverse_https and connect to host.com:443" ascii //weight: 1
        $x_1_6 = "setting the filename to \"2_host.com_443.exe\" and running it witho" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TinyMet_MS_2147768105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TinyMet.MS!MTB"
        threat_id = "2147768105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TinyMet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 08 56 8b 45 ?? 89 45 ?? c7 45 ?? ?? ?? ?? ?? 8b 4d ?? 69 c9 ?? ?? ?? ?? 89 4d ?? 8b 55 ?? 81 ea ?? ?? ?? ?? 89 55 ?? a1 ?? ?? ?? ?? 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {89 02 5f 5d c3 2d 00 31 0d ?? ?? ?? ?? c7 05 [0-8] a1 ?? ?? ?? ?? 01 05 [0-6] 8b 15 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

