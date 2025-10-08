rule Trojan_Win32_ReverseShellz_A_2147954502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ReverseShellz.A!MTB"
        threat_id = "2147954502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ReverseShellz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reverse-shell3" ascii //weight: 1
        $x_1_2 = "Failed to resolve server's IP address." ascii //weight: 1
        $x_1_3 = "Connected to the server." ascii //weight: 1
        $x_1_4 = "CMD process started successfully." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

