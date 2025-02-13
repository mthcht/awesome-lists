rule Trojan_Win32_Babadeda_RPD_2147836244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babadeda.RPD!MTB"
        threat_id = "2147836244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babadeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "copy delete.exe C:\\WINDOWS" ascii //weight: 1
        $x_1_2 = "copy expand.exe C:\\WINDOWS" ascii //weight: 1
        $x_1_3 = "echo y | reg add" ascii //weight: 1
        $x_1_4 = "NoControlPanel" ascii //weight: 1
        $x_1_5 = "NoViewOnDrive" ascii //weight: 1
        $x_1_6 = "NoDriveTypeAutoRun" ascii //weight: 1
        $x_1_7 = "DisableTaskMgr" ascii //weight: 1
        $x_1_8 = "disableregistrytools" ascii //weight: 1
        $x_1_9 = "DisableCMD" ascii //weight: 1
        $x_1_10 = "taskkill /f /im explorer.exe" ascii //weight: 1
        $x_1_11 = "start random.bat" ascii //weight: 1
        $x_1_12 = "start delete.exe" ascii //weight: 1
        $x_1_13 = "taskkill /f /im cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Babadeda_GMH_2147889331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Babadeda.GMH!MTB"
        threat_id = "2147889331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Babadeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Env_DX8\\Nostalgia.exe" ascii //weight: 1
        $x_1_2 = "XYkLVXSF" ascii //weight: 1
        $x_1_3 = "XT@FhmacB" ascii //weight: 1
        $x_1_4 = "af16zd6" ascii //weight: 1
        $x_1_5 = "\\Env_DX9\\Conquer.exe" ascii //weight: 1
        $x_1_6 = "Program Files\\AutoPatch.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

