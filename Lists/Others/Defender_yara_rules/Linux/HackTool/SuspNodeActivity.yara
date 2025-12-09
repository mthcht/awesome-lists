rule HackTool_Linux_SuspNodeActivity_A_2147959056_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspNodeActivity.A"
        threat_id = "2147959056"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspNodeActivity"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $n_100_1 = "bun.sh" wide //weight: -100
        $n_100_2 = "jbang.dev" wide //weight: -100
        $n_100_3 = "byted.org" wide //weight: -100
        $n_100_4 = "/admin-api/connect" wide //weight: -100
        $n_100_5 = "posthog" wide //weight: -100
        $n_100_6 = "claude" wide //weight: -100
        $n_100_7 = "localhost" wide //weight: -100
        $x_20_8 = {2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00 20 00 2d 00 63 00 [0-128] 63 00 75 00 72 00 6c 00 20 00}  //weight: 20, accuracy: Low
        $x_20_9 = {2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00 20 00 2d 00 63 00 [0-128] 77 00 67 00 65 00 74 00 20 00}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

