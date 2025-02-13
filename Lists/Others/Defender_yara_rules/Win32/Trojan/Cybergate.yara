rule Trojan_Win32_Cybergate_ADK_2147828592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cybergate.ADK!MTB"
        threat_id = "2147828592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cybergate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Blau]Delimitador[Blau]" wide //weight: 1
        $x_1_2 = "TVpQAAIAAAAEAA8A//8AALgAAAAAAAAAQAAaAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

