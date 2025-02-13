rule VirTool_Win32_WierdFunguz_A_2147808501_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/WierdFunguz.A!MTB"
        threat_id = "2147808501"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "WierdFunguz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ViolentFungus-C2-main\\src\\CommandHandler." ascii //weight: 1
        $x_1_2 = "\\src\\ServiceTcpProcessor." ascii //weight: 1
        $x_1_3 = "ViolentFungus-C2-main\\src\\DataRequestProcessor." ascii //weight: 1
        $x_1_4 = "\\src\\ServiceTcp." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

