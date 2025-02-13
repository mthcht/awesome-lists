rule Backdoor_Win64_Dridex_AX_2147786455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Dridex.AX!MTB"
        threat_id = "2147786455"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DsReplicaDelW" ascii //weight: 3
        $x_3_2 = "DsFreePasswordCredentials" ascii //weight: 3
        $x_3_3 = "B.omprzy" ascii //weight: 3
        $x_3_4 = "@.cvl" ascii //weight: 3
        $x_3_5 = "FmtIdToPropStgName" ascii //weight: 3
        $x_3_6 = "ShellExecuteExA" ascii //weight: 3
        $x_3_7 = "SetupCommitFileQueueW" ascii //weight: 3
        $x_3_8 = "SetupQuerySpaceRequiredOnDriveW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Dridex_AY_2147787521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Dridex.AY!MTB"
        threat_id = "2147787521"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ba 57 96 51 8f a1 af dc 1b d0 88 e1 8d f6 93 99 cf a9 c7 9c f0 46 d7 78 bf 47 d9 9b ca fb d1 15}  //weight: 10, accuracy: High
        $x_10_2 = "zG}0(T9YH;SvW]%q,a/Ar1h+{*|)wprGE<m=Jfv%=" ascii //weight: 10
        $x_3_3 = "MprConfigGetFriendlyName" ascii //weight: 3
        $x_3_4 = "MprAdminInterfaceSetInfo" ascii //weight: 3
        $x_3_5 = "MprConfigServerDisconnect" ascii //weight: 3
        $x_3_6 = "MprAdminUserGetInfo" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

