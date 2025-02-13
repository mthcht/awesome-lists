rule Backdoor_MSIL_ShellClient_A_2147798508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/ShellClient.A!dll"
        threat_id = "2147798508"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellClient"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 14 1c 8d ?? 00 00 01 25 16 7e ?? 00 00 04 a2 25 17 02 a2 25 18 7e ?? 00 00 04 a2 25 19 28 ?? 00 00 06 a2 25 1a 28 ?? 00 00 06 a2 25 1b 03 2d 07 7e ?? 00 00 0a 2b 05 28 ?? 00 00 06 a2 14 28 ?? 00 00 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_ShellClient_A_2147798509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/ShellClient.A"
        threat_id = "2147798509"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "costura." ascii //weight: 1
        $x_1_2 = "clientcore.dll" ascii //weight: 1
        $x_1_3 = "extensionlib.dll" ascii //weight: 1
        $x_1_4 = "dll.compressed" ascii //weight: 1
        $x_1_5 = "DcSvc.DropboxApi+<Upload>" ascii //weight: 1
        $x_1_6 = "/LogToConsole=false/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

