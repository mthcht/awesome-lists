rule HackTool_Win32_Dnscat_A_2147833861_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Dnscat.A"
        threat_id = "2147833861"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Dnscat"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "COMMAND_EXEC [request] :: request_id: 0x%04x :: name: %s :: command: %s" ascii //weight: 1
        $x_1_2 = "TUNNEL_DATA [request] :: request_id 0x%04x :: tunnel_id %d" ascii //weight: 1
        $x_1_3 = "Sophic" ascii //weight: 1
        $x_1_4 = "dnscat2.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

