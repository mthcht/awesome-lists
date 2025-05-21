rule Trojan_MSIL_ShellcodeInject_AX_2147905008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeInject.AX!MTB"
        threat_id = "2147905008"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Trarengvat Flfpnyy fghof vf abg fhccbegrq sbe JBJ6" wide //weight: 1
        $x_1_2 = "OneDriveHelper.dll" wide //weight: 1
        $x_1_3 = "shellcode" ascii //weight: 1
        $x_1_4 = {28 52 01 00 06 13 04 11 04 16 8d 50 00 00 01 33 01 2a 1f 10 8d 50 00 00 01 13 05 28 87 00 00 0a 25 17 6f 88 00 00 0a 25 18 6f 89 00 00 0a 25 09 6f 8a 00 00 0a 25 11 05 6f 8b 00 00 0a 6f 8c 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellcodeInject_CFN_2147941803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeInject.CFN!MTB"
        threat_id = "2147941803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Queue of target process. PoolParty Success!" ascii //weight: 1
        $x_1_2 = "malicious TP_JOB" ascii //weight: 1
        $x_1_3 = "sacrificial edge process will be created for the injection" ascii //weight: 1
        $x_1_4 = "Writing shellcode to start routine address" ascii //weight: 1
        $x_1_5 = "worker factory start routine, bytesWritten" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

