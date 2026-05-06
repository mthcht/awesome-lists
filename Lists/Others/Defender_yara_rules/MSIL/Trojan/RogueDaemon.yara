rule Trojan_MSIL_RogueDaemon_DB_2147968533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RogueDaemon.DB!MTB"
        threat_id = "2147968533"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RogueDaemon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InfoGatherer" ascii //weight: 1
        $x_1_2 = "AdapterInfoEx" ascii //weight: 1
        $x_1_3 = "ComputerNameEx" ascii //weight: 1
        $x_1_4 = "UserAgentEx" ascii //weight: 1
        $x_1_5 = "GetRc4KeyFromUrl" ascii //weight: 1
        $x_1_6 = "InfoCollector.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

