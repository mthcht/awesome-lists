rule VirTool_MSIL_Mythagent_A_2147793998_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Mythagent.A"
        threat_id = "2147793998"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mythagent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Apollo.Evasion" ascii //weight: 1
        $x_1_2 = "Apollo.Jobs" ascii //weight: 1
        $x_1_3 = "Apollo.CommandModules" ascii //weight: 1
        $x_1_4 = "Mythic.C2Profiles" ascii //weight: 1
        $x_1_5 = "MythicServerResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Mythagent_B_2147794104_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Mythagent.B"
        threat_id = "2147794104"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mythagent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Apollo.Management.C2" ascii //weight: 1
        $x_1_2 = "Apollo.Peers.SMB" ascii //weight: 1
        $x_1_3 = "GetMythicUUID" ascii //weight: 1
        $x_1_4 = "Apollo.Peers.TCP" ascii //weight: 1
        $x_1_5 = "mythicFileId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Mythagent_B_2147794104_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Mythagent.B"
        threat_id = "2147794104"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mythagent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Jitter: {" wide //weight: 1
        $x_1_2 = "Domains: {" wide //weight: 1
        $x_1_3 = "Proxy Address: {" wide //weight: 1
        $x_1_4 = "kill_date" wide //weight: 1
        $x_1_5 = "host_header" wide //weight: 1
        $x_1_6 = {4b 69 6c 6c 4a 6f 62 00}  //weight: 1, accuracy: High
        $x_1_7 = {47 65 74 4a 6f 62 73 00}  //weight: 1, accuracy: High
        $x_1_8 = "AmsiScanBuffer" wide //weight: 1
        $x_1_9 = "EtwEventWrite" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

