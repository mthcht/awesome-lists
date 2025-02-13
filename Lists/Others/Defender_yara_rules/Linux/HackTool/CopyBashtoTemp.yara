rule HackTool_Linux_CopyBashtoTemp_A_2147769048_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CopyBashtoTemp.A"
        threat_id = "2147769048"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CopyBashtoTemp"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cp -i /bin/bash /tmp/" wide //weight: 10
        $x_10_2 = "cp /bin/bash /tmp/" wide //weight: 10
        $x_10_3 = "cp -i /bin/sh /tmp/" wide //weight: 10
        $x_10_4 = "cp /bin/sh /tmp/" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

