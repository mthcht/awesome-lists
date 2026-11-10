rule Trojan_Linux_SleepyDuck_DA_2147981817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SleepyDuck.DA!MTB"
        threat_id = "2147981817"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SleepyDuck"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "evjawbreaker/internal/hubclient.Run" ascii //weight: 10
        $x_10_2 = "evjawbreaker/internal/hubclient.startShellLocked" ascii //weight: 10
        $x_10_3 = "evjawbreaker/internal/hubclient.runCommand" ascii //weight: 10
        $x_10_4 = "evjawbreaker/internal/hubclient.runOneUnixCommandLocked" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

