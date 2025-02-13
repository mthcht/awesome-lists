rule PWS_MSIL_Remcos_AA_2147772555_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Remcos.AA!MTB"
        threat_id = "2147772555"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_SplashScreen1" ascii //weight: 1
        $x_1_2 = "add_MouseDoubleClick" ascii //weight: 1
        $x_1_3 = "NotifyIcon1_MouseClick" ascii //weight: 1
        $x_1_4 = "set_CheckOnClick" ascii //weight: 1
        $x_1_5 = "get_AccessToTheOfficialWebsiteOnGitHubToolStripMenuItem" ascii //weight: 1
        $x_1_6 = "AutoSaveSettings" ascii //weight: 1
        $x_1_7 = "KeyPressEventArgs" ascii //weight: 1
        $x_1_8 = "add_KeyPress" ascii //weight: 1
        $x_1_9 = "config\\name-list.xml" wide //weight: 1
        $x_1_10 = "config\\job-list.xml" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

