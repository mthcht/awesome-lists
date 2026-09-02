rule Trojan_Win64_CouchPotato_DA_2147977373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CouchPotato.DA!MTB"
        threat_id = "2147977373"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CouchPotato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\pipe\\CouchPotato\\pipe\\srvsvc" ascii //weight: 1
        $x_1_2 = "\\pipe\\efsrpc" ascii //weight: 1
        $x_1_3 = "EfsRpcQueryUsersOnFile" ascii //weight: 1
        $x_1_4 = "ImpersonateNamedPipeClient" ascii //weight: 1
        $x_1_5 = "NtDuplicateToken" ascii //weight: 1
        $x_1_6 = "CreateProcessAsUserW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

