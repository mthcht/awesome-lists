rule Trojan_Win64_jscramSteal_DA_2147973471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/jscramSteal.DA!MTB"
        threat_id = "2147973471"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "jscramSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "agent.pdb" ascii //weight: 1
        $x_1_2 = "sqlite_rename_test" ascii //weight: 1
        $x_1_3 = "winLockSharedMemory" ascii //weight: 1
        $x_1_4 = "CREATE TABLE x" ascii //weight: 1
        $x_1_5 = "json_pretty" ascii //weight: 1
        $x_1_6 = "GetExtendedTcpTable" ascii //weight: 1
        $x_1_7 = "WSASocketW" ascii //weight: 1
        $x_1_8 = "?\\UNC\\.\\strings" ascii //weight: 1
        $x_1_9 = "cmd.exe /e:ON /v:OFF /d /c" ascii //weight: 1
        $x_1_10 = "\\\\?\\\\\\handlepath*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

