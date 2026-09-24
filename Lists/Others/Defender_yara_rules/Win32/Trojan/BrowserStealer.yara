rule Trojan_Win32_BrowserStealer_A_2147978733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BrowserStealer.A!MTB"
        threat_id = "2147978733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BrowserStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[MAIN] Not elevated, spawning UAC bypass for harvest in background thread" ascii //weight: 1
        $x_1_2 = "Harvesting Chrome browser data" ascii //weight: 1
        $x_1_3 = "[HARVEST] ========== 0x10 BROWSER DATA REQUEST HANDLER" ascii //weight: 1
        $x_1_4 = "[HARVEST] Response will now be sent to C2" ascii //weight: 1
        $x_1_5 = "browser data request: sending %zu bytes (JSON)" ascii //weight: 1
        $x_1_6 = "Starting RDP agent (main loop)" ascii //weight: 1
        $x_1_7 = "Generated machine id %s (stored at %s)" ascii //weight: 1
        $x_1_8 = "no PING for %u ms; treating the connection as dead" ascii //weight: 1
        $x_1_9 = "86.109.75.165" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

