rule HackTool_MacOS_SuspDataCollection_PC_2147932067_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspDataCollection.PC"
        threat_id = "2147932067"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspDataCollection"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; launchctl list" wide //weight: 10
        $x_10_2 = "_bs >/dev/null ; launchctl print " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

