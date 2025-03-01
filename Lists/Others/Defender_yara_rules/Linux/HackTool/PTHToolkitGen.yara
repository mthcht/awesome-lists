rule HackTool_Linux_PTHToolkitGen_YY_2147767893_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PTHToolkitGen.YY"
        threat_id = "2147767893"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PTHToolkitGen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "pth-net" wide //weight: 20
        $x_20_2 = "pth-rpcclient" wide //weight: 20
        $x_20_3 = "pth-smbclient" wide //weight: 20
        $x_20_4 = "pth-smbget" wide //weight: 20
        $x_20_5 = "pth-winexe" wide //weight: 20
        $x_20_6 = "pth-wmic" wide //weight: 20
        $x_20_7 = "pth-wmis" wide //weight: 20
        $x_20_8 = "pth-sqsh" wide //weight: 20
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Linux_PTHToolkitGen_WW_2147768899_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PTHToolkitGen.WW"
        threat_id = "2147768899"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PTHToolkitGen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "smbhash" wide //weight: 10
        $x_5_2 = "//" wide //weight: 5
        $x_1_3 = "-u" wide //weight: 1
        $x_1_4 = "-a" wide //weight: 1
        $x_1_5 = "-runas" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

