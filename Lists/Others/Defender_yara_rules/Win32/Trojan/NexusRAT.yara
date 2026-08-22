rule Trojan_Win32_NexusRAT_ANK_2147976776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NexusRAT.ANK!MTB"
        threat_id = "2147976776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NexusRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "NexusRAT_Mtx_Default" ascii //weight: 3
        $x_3_2 = "FAKE SYSTEM PROCESS - '%s' running from '%s' instead of legitimate path" ascii //weight: 3
        $x_3_3 = "0987samnta.duckdns.org" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

