rule Trojan_Win32_BrobanDel_A_2147690456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BrobanDel.A"
        threat_id = "2147690456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanDel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunLegacyCPLElevated.exe Shell32.dll,Control_RunDLL" ascii //weight: 1
        $x_1_2 = "extensions.shownSelectionUI" ascii //weight: 1
        $x_1_3 = "extensions.autoDisableScopes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

