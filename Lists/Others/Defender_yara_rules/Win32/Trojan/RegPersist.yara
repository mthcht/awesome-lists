rule Trojan_Win32_RegPersist_ZA_2147959777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RegPersist.ZA!MTB"
        threat_id = "2147959777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RegPersist"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = ".exe --password" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

