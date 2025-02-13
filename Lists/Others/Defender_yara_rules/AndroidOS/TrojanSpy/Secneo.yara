rule TrojanSpy_AndroidOS_Secneo_A_2147785280_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Secneo.A!xp"
        threat_id = "2147785280"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Secneo"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/com.secneo.tmp" ascii //weight: 1
        $x_1_2 = "com/secshell/secData/FilesFileObserver" ascii //weight: 1
        $x_1_3 = "PasswordObserver" ascii //weight: 1
        $x_1_4 = "hd.fish.WxMonitor.WxMonitorApplication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Secneo_D_2147797094_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Secneo.D!MTB"
        threat_id = "2147797094"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Secneo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "has_fileobserver" ascii //weight: 1
        $x_1_2 = "/com.secneo.tmp" ascii //weight: 1
        $x_1_3 = "com/secshell/secData/FilesFileObserver" ascii //weight: 1
        $x_1_4 = "PasswordObserver" ascii //weight: 1
        $x_1_5 = "com.gsoft.ASEPq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

