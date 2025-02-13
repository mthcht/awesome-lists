rule VirTool_MSIL_Injantivm_GG_2147769552_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injantivm.GG!MTB"
        threat_id = "2147769552"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injantivm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\VMware" ascii //weight: 1
        $x_1_3 = "sandboxierpcss" ascii //weight: 1
        $x_1_4 = "pcalua.exe" ascii //weight: 1
        $x_1_5 = "InstallUtil.exe" ascii //weight: 1
        $x_1_6 = "RegAsm.exe" ascii //weight: 1
        $x_1_7 = "AddInProcess32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

