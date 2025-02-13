rule Backdoor_MacOS_Opinion_C_2147746123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Opinion.C!MTB"
        threat_id = "2147746123"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Opinion"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MacAnalyser/macanalyser/MMProcessInfo.cpp" ascii //weight: 1
        $x_1_2 = "setShell" ascii //weight: 1
        $x_1_3 = "/var/run/OSMIMPQ.socket" ascii //weight: 1
        $x_1_4 = "http://localhost:8254/qryChromePid.pid=%d" ascii //weight: 1
        $x_1_5 = "MacAnalyser/OSMIMHK/osmimhk/mach_override.c" ascii //weight: 1
        $x_1_6 = "swizzlesafari" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

