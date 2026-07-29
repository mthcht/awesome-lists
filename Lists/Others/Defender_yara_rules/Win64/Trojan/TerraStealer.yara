rule Trojan_Win64_TerraStealer_GXT_2147974776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TerraStealer.GXT!MTB"
        threat_id = "2147974776"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TerraStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Direct Syscall-Based Reflective Hollowing" ascii //weight: 2
        $x_2_2 = "BrowserDiscovery::FindAll: scanning %zu browser types" ascii //weight: 2
        $x_2_3 = "ProcessBrowser: name=%s version=%s exe=%ls killFirst=%d" ascii //weight: 2
        $x_2_4 = "\\ProgramData\\xlog.txt" ascii //weight: 2
        $x_2_5 = "No supported browsers found, exiting" ascii //weight: 2
        $x_2_6 = "AvastBrowser.exe" ascii //weight: 2
        $x_2_7 = "Creating suspended process" ascii //weight: 2
        $x_2_8 = "Payload client connected" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

