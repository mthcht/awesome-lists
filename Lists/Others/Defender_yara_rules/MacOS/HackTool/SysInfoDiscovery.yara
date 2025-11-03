rule HackTool_MacOS_SysInfoDiscovery_JX_2147956585_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SysInfoDiscovery.JX"
        threat_id = "2147956585"
        type = "HackTool"
        platform = "MacOS: "
        family = "SysInfoDiscovery"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "osascript" wide //weight: 20
        $x_20_2 = "-l javascript" wide //weight: 20
        $x_20_3 = "-e eval" wide //weight: 20
        $x_20_4 = "$.nsdata.datawithcontentsofurl" wide //weight: 20
        $x_20_5 = "orchard" wide //weight: 20
        $x_1_6 = "get_od_objectclass" wide //weight: 1
        $x_1_7 = "get_od_node_configuration" wide //weight: 1
        $x_1_8 = "convertto_sid" wide //weight: 1
        $x_1_9 = "convertfrom_sid" wide //weight: 1
        $x_1_10 = "get_domainuser" wide //weight: 1
        $x_1_11 = "get_localuser" wide //weight: 1
        $x_1_12 = "get_domaincomputer" wide //weight: 1
        $x_1_13 = "get_domainsid" wide //weight: 1
        $x_1_14 = "get_domaingroup" wide //weight: 1
        $x_1_15 = "get_localgroup" wide //weight: 1
        $x_1_16 = "get_domaingroupmember" wide //weight: 1
        $x_1_17 = "get_localgroupmember" wide //weight: 1
        $x_1_18 = "get_currentdomain" wide //weight: 1
        $x_1_19 = "get_currentnetbiosdomain" wide //weight: 1
        $x_1_20 = "get_forest" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_20_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

