rule Trojan_MacOS_SuspSupplyRAT_A_2147966052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspSupplyRAT.A"
        threat_id = "2147966052"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspSupplyRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "var/db/.AppleSetupDone" ascii //weight: 2
        $x_1_2 = "machdep.cpu.brand_string" ascii //weight: 1
        $x_1_3 = "/private/tmp/.%s" ascii //weight: 1
        $x_1_4 = "codesign --force --deep --sign" ascii //weight: 1
        $x_1_5 = "/usr/bin/osascript" ascii //weight: 1
        $x_1_6 = "rsp_kill" ascii //weight: 1
        $x_1_7 = "peinject" ascii //weight: 1
        $x_1_8 = "rsp_peinject" ascii //weight: 1
        $x_1_9 = "runscript" ascii //weight: 1
        $x_1_10 = "rsp_runscript" ascii //weight: 1
        $x_1_11 = "rsp_rundir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

