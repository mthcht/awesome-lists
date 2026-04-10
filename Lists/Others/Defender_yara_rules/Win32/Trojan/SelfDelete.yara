rule Trojan_Win32_SelfDelete_SV_2147966644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SelfDelete.SV!MTB"
        threat_id = "2147966644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SelfDelete"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SelfDelete.exe" ascii //weight: 1
        $x_1_2 = "SelfDelete.exe -del -f" wide //weight: 1
        $x_1_3 = "Could not rename file!" wide //weight: 1
        $x_1_4 = "deleted successfully" wide //weight: 1
        $x_1_5 = "Delete the executable of the currently running process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

