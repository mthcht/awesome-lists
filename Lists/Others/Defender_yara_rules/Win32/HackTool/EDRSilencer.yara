rule HackTool_Win32_EDRSilencer_DA_2147956659_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/EDRSilencer.DA!MTB"
        threat_id = "2147956659"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "EDRSilencer"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\\\Silent.bin" ascii //weight: 10
        $x_1_2 = "EDR Outbound Block" ascii //weight: 1
        $x_1_3 = "EDR Inbound Block" ascii //weight: 1
        $x_1_4 = "wsftprm.sys" ascii //weight: 1
        $x_1_5 = "[+] Successfully blocked communications for %s" ascii //weight: 1
        $x_1_6 = "traffic from EDR process" ascii //weight: 1
        $x_10_7 = "EDR Network Silencer v" ascii //weight: 10
        $x_1_8 = "Block IPv4 outbound connections" ascii //weight: 1
        $x_1_9 = "Block IPv6 outbound connections" ascii //weight: 1
        $x_1_10 = "Block IPv4 inbound connections" ascii //weight: 1
        $x_1_11 = "Block IPv6 inbound connections" ascii //weight: 1
        $x_1_12 = "Beginning EDR network isolation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

