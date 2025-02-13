rule PWS_Win32_Vipgsm_V_2147600064_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Vipgsm.V"
        threat_id = "2147600064"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Vipgsm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kaspersky-labs" ascii //weight: 1
        $x_1_2 = "viruslist" ascii //weight: 1
        $x_1_3 = "symatec" ascii //weight: 1
        $x_1_4 = "update.symantec" ascii //weight: 1
        $x_1_5 = "symantecliveupdate" ascii //weight: 1
        $x_1_6 = "sophos" ascii //weight: 1
        $x_1_7 = "norton" ascii //weight: 1
        $x_1_8 = "mcafee" ascii //weight: 1
        $x_1_9 = "liveupdate.symantecliveupdate" ascii //weight: 1
        $x_1_10 = "f-secure" ascii //weight: 1
        $x_1_11 = "secure.nai" ascii //weight: 1
        $x_1_12 = "my-etrust" ascii //weight: 1
        $x_1_13 = "networkassociates" ascii //weight: 1
        $x_1_14 = "trendmicro" ascii //weight: 1
        $x_1_15 = "grisoft" ascii //weight: 1
        $x_1_16 = "sandbox.norman" ascii //weight: 1
        $x_1_17 = "uk.trendmicro-europe" ascii //weight: 1
        $x_1_18 = "TcpCheckInit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

