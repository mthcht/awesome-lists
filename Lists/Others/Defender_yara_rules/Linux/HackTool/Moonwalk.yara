rule HackTool_Linux_Moonwalk_A_2147891906_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Moonwalk.A!MTB"
        threat_id = "2147891906"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Moonwalk"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MOONWALK" ascii //weight: 1
        $x_1_2 = "bin/touch-t-m-a/.MOONWALK" ascii //weight: 1
        $x_1_3 = "/find-maxdepth3-typed-perm-777src/core/recon.rs.MOONWALK" ascii //weight: 1
        $x_1_4 = "src/core/logger.rs" ascii //weight: 1
        $x_1_5 = "/var/log/utmp/var/log/wtmp/var/log/system.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

