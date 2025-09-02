rule HackTool_Linux_PreloadHijack_A_2147951154_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PreloadHijack.A"
        threat_id = "2147951154"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PreloadHijack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".snow_valley" ascii //weight: 10
        $x_1_2 = "ld.so.preload" ascii //weight: 1
        $x_10_3 = "evil_rabbit" ascii //weight: 10
        $x_10_4 = "PEACE_FLAG" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

