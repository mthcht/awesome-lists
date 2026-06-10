rule Backdoor_MSIL_KeyLogger_AAC_2147971286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/KeyLogger.AAC!AMTB"
        threat_id = "2147971286"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Salih\\Downloads\\csharp-keylogger-master\\csharp-keylogger-master\\KeyLogger\\KeyLogger\\obj\\Debug\\KeyLogger.pdb" ascii //weight: 10
        $x_2_2 = "KeyLogger.exe" ascii //weight: 2
        $x_2_3 = "\\Log.txt" wide //weight: 2
        $x_2_4 = "[Print Screen]" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_KeyLogger_AAD_2147971287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/KeyLogger.AAD!AMTB"
        threat_id = "2147971287"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell.exe cmd.exe _/_c_" wide //weight: 2
        $x_2_2 = "\\d_i_r._t_x_t" wide //weight: 2
        $x_2_3 = "\\Prcss_Respawner.exe" wide //weight: 2
        $x_2_4 = "[logar]<'''>" wide //weight: 2
        $x_2_5 = "[logar]<'''>File was started with Sucess<'''>" wide //weight: 2
        $x_2_6 = "[logar]<'''>Desktop Remote Initialized with Sucess!<'''>" wide //weight: 2
        $x_2_7 = "[start_processrespawner]" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_KeyLogger_AAE_2147971288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/KeyLogger.AAE!AMTB"
        threat_id = "2147971288"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KeyLogger"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\moatsem\\Desktop\\Arya\\XeytanKeylogger\\obj\\Debug\\Arya.pdb" ascii //weight: 2
        $x_2_2 = "StartKeyLog_CheckedChanged" ascii //weight: 2
        $x_2_3 = "_monitorClipboard" ascii //weight: 2
        $x_2_4 = "Arya.exe" ascii //weight: 2
        $x_2_5 = "TakeScreenShot_Click" ascii //weight: 2
        $x_2_6 = "\\KeyL.html" wide //weight: 2
        $x_2_7 = "Start Key Log" wide //weight: 2
        $x_2_8 = "--- WebcamScreenshot ---" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

