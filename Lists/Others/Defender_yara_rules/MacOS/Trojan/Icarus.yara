rule Trojan_MacOS_Icarus_AMTB_2147980276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Icarus!AMTB"
        threat_id = "2147980276"
        type = "Trojan"
        platform = "MacOS: "
        family = "Icarus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://escapeai.live/uploadUpload" ascii //weight: 2
        $x_2_2 = "FilegrabberHTTP" ascii //weight: 2
        $x_2_3 = "runtime.stealWork" ascii //weight: 2
        $x_1_4 = "traceLocker.ProcSteal" ascii //weight: 1
        $x_1_5 = "/ICMacOs/browsingdata.GetLoginData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

