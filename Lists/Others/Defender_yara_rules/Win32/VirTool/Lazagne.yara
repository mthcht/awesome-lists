rule VirTool_Win32_Lazagne_A_2147816169_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Lazagne.A!MTB"
        threat_id = "2147816169"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazagne"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".windows.creddump7.win32.hashdump" ascii //weight: 1
        $x_1_2 = ".windows.creddump7.win32.lsasecrets" ascii //weight: 1
        $x_1_3 = ".config.execute_cmd" ascii //weight: 1
        $x_1_4 = ".config.DPAPI.vault" ascii //weight: 1
        $x_1_5 = ".config.DPAPI.credfile" ascii //weight: 1
        $x_1_6 = ".softwares.windows.lsa_secrets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

