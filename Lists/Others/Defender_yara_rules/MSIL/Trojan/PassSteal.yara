rule Trojan_MSIL_PassSteal_A_2147768515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PassSteal.A!MTB"
        threat_id = "2147768515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PassSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/create /sc MINUTE /mo 10 /tn \"Windows Defender Update System Folder\" /tr \"" ascii //weight: 1
        $x_1_2 = "https://iplogger.org/" ascii //weight: 1
        $x_1_3 = "https://pastebin.com/raw/" ascii //weight: 1
        $x_1_4 = "Windows Defenfer Logger File.exe" ascii //weight: 1
        $x_1_5 = "QXBwRGF0YQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

