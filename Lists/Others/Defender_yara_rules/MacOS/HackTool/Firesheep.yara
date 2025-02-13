rule HackTool_MacOS_Firesheep_A_2147750935_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Firesheep.A!MTB"
        threat_id = "2147750935"
        type = "HackTool"
        platform = "MacOS: "
        family = "Firesheep"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.codebutler.firesheep.backend" ascii //weight: 2
        $x_1_2 = "visitation_impl_invoke" ascii //weight: 1
        $x_1_3 = "osx_run_privileged: AuthorizationExecuteWithPrivileges()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

