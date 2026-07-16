rule Backdoor_Win64_FluffKitten_A_2147973594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/FluffKitten.A!dha"
        threat_id = "2147973594"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "FluffKitten"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pipe_client is None" ascii //weight: 1
        $x_1_2 = "unmarshal req fail" ascii //weight: 1
        $x_1_3 = "client_id=&client_secret=&scope=https://graph.microsoft.com/.default&grant_type=client_credentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_FluffKitten_B_2147973595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/FluffKitten.B!dha"
        threat_id = "2147973595"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "FluffKitten"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\myadmin\\.cargo\\" ascii //weight: 1
        $x_1_2 = "\\\\.\\pipe\\pipe_UDCClientBrokerServer_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

