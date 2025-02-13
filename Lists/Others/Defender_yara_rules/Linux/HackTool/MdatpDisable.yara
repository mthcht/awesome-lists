rule HackTool_Linux_MdatpDisable_DK9_2147928942_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/MdatpDisable.DK9"
        threat_id = "2147928942"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "MdatpDisable"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "killall wdavdaemon" wide //weight: 10
        $x_10_2 = "killall telemetryd_v2" wide //weight: 10
        $x_10_3 = "systemctl stop mdatp" wide //weight: 10
        $x_10_4 = "systemctl stop mde_netfilter" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

