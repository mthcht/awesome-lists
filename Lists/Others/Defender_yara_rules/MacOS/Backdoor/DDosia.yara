rule Backdoor_MacOS_DDosia_K_2147906332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/DDosia.K!MTB"
        threat_id = "2147906332"
        type = "Backdoor"
        platform = "MacOS: "
        family = "DDosia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dtracesemacquiredebug" ascii //weight: 1
        $x_1_2 = "heap dumpasyncpreemptoffforce" ascii //weight: 1
        $x_1_3 = "Pointermime/multipartwrite " ascii //weight: 1
        $x_1_4 = "HanLaoMroNkoVaiudpTCPUDP" ascii //weight: 1
        $x_1_5 = "callGOMEMLIMITBad varintatomic" ascii //weight: 1
        $x_1_6 = "0atomicor8tracebackrwxrwxrwxcomplex64math" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_DDosia_A_2147923772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/DDosia.A!MTB"
        threat_id = "2147923772"
        type = "Backdoor"
        platform = "MacOS: "
        family = "DDosia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {90 0b 40 f9 ff 63 30 eb c9 03 00 54 fe 0f 1e f8 fd 83 1f f8 fd 23 00 d1 1b 29 00 90 61 8f 42 f9 1b 29 00 90 62 8b 42 f9 1f 00 01 eb 2a 01 00 54 42 02 00 54 43 10 00 8b 61 04 40 f9 03 ec 7c d3 40 68 63 f8 fd fb 7f a9 ff 83 00 91}  //weight: 1, accuracy: High
        $x_1_2 = {3f 00 00 f1 c9 00 00 54 40 00 40 f9 41 04 40 f9 fd fb 7f a9 ff 83 00 91 c0 03 5f d6 e0 03 1f aa e1 03 00 aa 33 98 01 94 36 98 01 94 1f 20 03 d5 e0 07 00 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

