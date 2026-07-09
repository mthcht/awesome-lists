rule Trojan_Win64_ModBeacon_RV_2147973202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ModBeacon.RV!MTB"
        threat_id = "2147973202"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ModBeacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "EXE_PATHGlobal\\CBP.QZKVM.Exe.Mutex" ascii //weight: 5
        $x_5_2 = "stdio iO5@sole" ascii //weight: 5
        $x_5_3 = "CM_ustom@" ascii //weight: 5
        $x_2_4 = "MODBEACON_WRAPPER_TOKEN_PATCH_V1" ascii //weight: 2
        $x_2_5 = "MODBEACON_AGENT_TOKEN_Y|__V1" ascii //weight: 2
        $x_1_6 = "CBPUserSvcMODBEACON_AGENT_RUNTIMEexe" ascii //weight: 1
        $x_1_7 = "CBPUserSvcAPP_RUNTIMEexe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

