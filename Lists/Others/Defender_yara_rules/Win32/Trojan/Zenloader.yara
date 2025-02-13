rule Trojan_Win32_Zenloader_C_2147784018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenloader.C"
        threat_id = "2147784018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "platformclientmain" ascii //weight: 10
        $x_10_2 = "runmodule" ascii //weight: 10
        $x_10_3 = "#5008#" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenloader_C_2147784018_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenloader.C"
        threat_id = "2147784018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "rundll32" wide //weight: 10
        $x_10_2 = ",platformclientmain" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

