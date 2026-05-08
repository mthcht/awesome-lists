rule Backdoor_MSIL_Caminho_AR_2147964113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Caminho.AR!AMTB"
        threat_id = "2147964113"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Caminho"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "caminhovbs" ascii //weight: 10
        $x_1_2 = "LogonTrigger" ascii //weight: 1
        $x_1_3 = "Microsoft.Win32.TaskScheduler.Properties" ascii //weight: 1
        $x_1_4 = "LazyList" ascii //weight: 1
        $x_1_5 = "DummyLogger" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Capture" ascii //weight: 1
        $x_1_8 = "set_UserAccountDomain" ascii //weight: 1
        $x_1_9 = "set_UserPassword" ascii //weight: 1
        $x_1_10 = "caminho" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Caminho_ARP_2147965352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Caminho.ARP!AMTB"
        threat_id = "2147965352"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Caminho"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "caminho" ascii //weight: 15
        $x_1_2 = "payloadBuffer" ascii //weight: 1
        $x_1_3 = "uacPayloadUrl" ascii //weight: 1
        $x_1_4 = "encodedPayloadUrl" ascii //weight: 1
        $x_1_5 = "encodedUrlPayload" ascii //weight: 1
        $x_1_6 = "DsCrackNames" ascii //weight: 1
        $x_1_7 = "AllowingStartOnRemoteAppSession" ascii //weight: 1
        $x_1_8 = "set_LogonType" ascii //weight: 1
        $x_1_9 = "set_UserPassword" ascii //weight: 1
        $x_1_10 = "set_UserAccountDomain" ascii //weight: 1
        $x_1_11 = "Microsoft.Win32.TaskScheduler.Trigger>.Add" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Caminho_K_2147968840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Caminho.K!AMTB"
        threat_id = "2147968840"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Caminho"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ExecutarMetodoVAI" ascii //weight: 1
        $x_1_2 = "VirtualMachineDetector" ascii //weight: 1
        $x_1_3 = "caminhovbs" ascii //weight: 1
        $x_1_4 = "payloadBuffer" ascii //weight: 1
        $x_1_5 = "nomedoarquivo" ascii //weight: 1
        $x_1_6 = {65 78 74 65 6e c3 a7 61 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

