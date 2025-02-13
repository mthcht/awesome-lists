rule HackTool_MacOS_SuspConfigChanges_PB_2147932066_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspConfigChanges.PB"
        threat_id = "2147932066"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspConfigChanges"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; plutil -insert " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

