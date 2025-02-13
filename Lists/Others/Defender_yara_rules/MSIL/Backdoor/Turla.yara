rule Backdoor_MSIL_Turla_DB_2147772390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Turla.DB!MTB"
        threat_id = "2147772390"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Turla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Agent.exe" ascii //weight: 1
        $x_1_2 = "Stopwatch" ascii //weight: 1
        $x_1_3 = "CreateRemoteThread" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
        $x_1_5 = "ConfuserEx v0.6.0" ascii //weight: 1
        $x_1_6 = "ConfusedByAttribute" ascii //weight: 1
        $x_1_7 = "Sysinternals DebugView" ascii //weight: 1
        $x_1_8 = "PublicKeyToken=b77a5c561934e089" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

