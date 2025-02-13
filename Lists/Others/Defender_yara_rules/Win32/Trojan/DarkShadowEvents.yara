rule Trojan_Win32_DarkShadowEvents_A_2147773771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkShadowEvents.A!dha"
        threat_id = "2147773771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkShadowEvents"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ScDeviceEnums" wide //weight: 2
        $x_1_2 = "VMware Physical Disk Helper Service" wide //weight: 1
        $x_1_3 = "CoreMessagingRegistrar" wide //weight: 1
        $x_1_4 = "OneSyncSvc_379e1" wide //weight: 1
        $x_1_5 = "Avg. Disk Queue Length" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

