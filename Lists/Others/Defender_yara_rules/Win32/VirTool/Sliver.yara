rule VirTool_Win32_Sliver_C_2147842379_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sliver.C"
        threat_id = "2147842379"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sliver"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bishopfox/sliver/protobuf/sliverpb" ascii //weight: 1
        $x_1_2 = "sliverpb/sliver.proto" ascii //weight: 1
        $x_1_3 = ".sliverpb.NetInterface" ascii //weight: 1
        $x_1_4 = ".sliverpb.FileInfo" ascii //weight: 1
        $x_1_5 = ".sliverpb.SockTabEntry.SockAddr" ascii //weight: 1
        $x_1_6 = ".sliverpb.DNSBlockHeader" ascii //weight: 1
        $x_1_7 = ".sliverpb.ServiceInfoReq" ascii //weight: 1
        $x_1_8 = ".sliverpb.PivotEntry" ascii //weight: 1
        $x_1_9 = ".sliverpb.WGTCPForwarder" ascii //weight: 1
        $x_1_10 = ".sliverpb.WGSocksServer" ascii //weight: 1
        $x_1_11 = ".sliverpb.WindowsPrivilegeEntry" ascii //weight: 1
        $x_1_12 = ".commonpb.Response" ascii //weight: 1
        $x_1_13 = ".commonpb.Request" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Sliver_A_2147842381_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sliver.A!MTB"
        threat_id = "2147842381"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sliverpb.Register.ActiveC2" ascii //weight: 1
        $x_1_2 = "sliverpb.KillSessionReq" ascii //weight: 1
        $x_1_3 = "sliverpb.Register.PidPid" ascii //weight: 1
        $x_1_4 = "sliverpb.IfconfigReq" ascii //weight: 1
        $x_1_5 = "sliverpb.TerminateReq" ascii //weight: 1
        $x_1_6 = "sliverpb.NetInterfaces" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Sliver_A_2147842381_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sliver.A!MTB"
        threat_id = "2147842381"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/xc/load.go" ascii //weight: 1
        $x_1_2 = "main.bake" ascii //weight: 1
        $x_1_3 = "syscall/zsyscall_windows.go" ascii //weight: 1
        $x_1_4 = {48 89 6c 24 30 48 8d ?? ?? ?? 48 8b 44 24 48 48 89 04 24 48 8b 44 24 40 48 89 44 24 08 e8 ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 89 04 24 48 c7 44 24 08 00 00 00 00 48 8b 44 24 40 48 89 44 24 10 48 c7 44 24 18 00 30 00 00 48 c7 44 24 20 04 00 00 00 e8 ?? ?? ?? ?? 48 8b 44 24 28 48 89 44 24 50 48 8b 6c 24 30 48 83 c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Sliver_A_2147842381_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sliver.A!MTB"
        threat_id = "2147842381"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sliverpb.NetInterface" ascii //weight: 1
        $x_1_2 = "sliverpb.WGSocksServer" ascii //weight: 1
        $x_1_3 = "sliverpb.PortfwdProtocol" ascii //weight: 1
        $x_1_4 = "sliverpb.WGTCPForwarder" ascii //weight: 1
        $x_1_5 = ".sliverpb.RegistryType" ascii //weight: 1
        $x_1_6 = ".sliverpb.WindowsPrivilegeEntryR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Sliver_A_2147842381_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sliver.A!MTB"
        threat_id = "2147842381"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "*sliverpb.Process" ascii //weight: 1
        $x_1_2 = {2a 73 6c 69 76 65 72 70 62 2e [0-32] 49 6e 66 6f}  //weight: 1, accuracy: Low
        $x_1_3 = "*sliverpb.Migrate" ascii //weight: 1
        $x_1_4 = "*sliverpb.Elevate" ascii //weight: 1
        $x_1_5 = {2a 73 6c 69 76 65 72 70 62 2e 4b 69 6c 6c [0-32] 52 65 71}  //weight: 1, accuracy: Low
        $x_1_6 = "*sliverpb.DNSPoll" ascii //weight: 1
        $x_1_7 = "*sliverpb.DNSBlockHeader" ascii //weight: 1
        $x_1_8 = "*sliverpb.ExecuteAssemblyReq" ascii //weight: 1
        $x_1_9 = "*sliverpb.ImpersonateReq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule VirTool_Win32_Sliver_A_2147842381_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sliver.A!MTB"
        threat_id = "2147842381"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 2e 47 65 74 50 69 64 [0-30] 29 2e 47 65 74 46 69 6c 65 6e 61 6d 65 [0-30] 29 2e 47 65 74 41 63 74 69 76 65 43 32 [0-30] 29 2e 47 65 74 56 65 72 73 69 6f 6e [0-30] 29 2e 47 65 74 52 65 63 6f 6e 6e 65 63 74 49 6e 74 65 72 76 61 6c [0-30] 29 2e 47 65 74 50 72 6f 78 79 55 52 4c}  //weight: 1, accuracy: Low
        $x_1_2 = {29 2e 47 65 74 45 78 65 63 75 74 61 62 6c 65 [0-30] 29 2e 47 65 74 4f 77 6e 65 72 [0-30] 29 2e 47 65 74 53 65 73 73 69 6f 6e 49 44 [0-30] 29 2e 47 65 74 43 6d 64 4c 69 6e 65}  //weight: 1, accuracy: Low
        $x_1_3 = {29 2e 47 65 74 54 61 72 67 65 74 4c 6f 63 61 74 69 6f 6e [0-30] 29 2e 47 65 74 52 65 66 65 72 65 6e 63 65 44 4c 4c [0-30] 29 2e 47 65 74 54 61 72 67 65 74 44 4c 4c [0-30] 29 2e 47 65 74 50 72 6f 66 69 6c 65 4e 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_4 = {29 2e 47 65 74 55 73 65 72 6e 61 6d 65 [0-30] 29 2e 47 65 74 50 61 73 73 77 6f 72 64 [0-30] 29 2e 47 65 74 44 6f 6d 61 69 6e [0-30] 29 2e 47 65 74 52 65 71 75 65 73 74}  //weight: 1, accuracy: Low
        $x_1_5 = {29 2e 47 65 74 50 72 6f 63 65 73 73 4e 61 6d 65 [0-30] 29 2e 47 65 74 41 72 67 73 [0-30] 29 2e 47 65 74 45 6e 74 72 79 50 6f 69 6e 74 [0-30] 29 2e 47 65 74 4b 69 6c 6c}  //weight: 1, accuracy: Low
        $x_1_6 = {29 2e 47 65 74 52 65 6d 6f 74 65 41 64 64 72 [0-30] 29 2e 47 65 74 53 6b 53 74 61 74 65 [0-30] 29 2e 47 65 74 55 49 44 [0-30] 29 2e 47 65 74 50 72 6f 63 65 73 73}  //weight: 1, accuracy: Low
        $x_1_7 = {29 2e 47 65 74 45 6e 61 62 6c 65 50 54 59 [0-30] 29 2e 47 65 74 50 69 64 [0-30] 29 2e 47 65 74 54 75 6e 6e 65 6c 49 44 [0-30] 29 2e 47 65 74 52 65 73 70 6f 6e 73 65}  //weight: 1, accuracy: Low
        $x_1_8 = {29 2e 47 65 74 4e 65 74 49 6e 74 65 72 66 61 63 65 73 [0-30] 29 2e 47 65 74 52 65 73 70 6f 6e 73 65 [0-30] 29 2e 52 65 73 65 74 [0-30] 29 2e 53 74 72 69 6e 67}  //weight: 1, accuracy: Low
        $x_1_9 = {29 2e 47 65 74 48 6f 73 74 6e 61 6d 65 [0-30] 29 2e 47 65 74 50 6f 72 74 [0-30] 29 2e 47 65 74 43 6f 6d 6d 61 6e 64 [0-30] 29 2e 47 65 74 50 61 73 73 77 6f 72 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Sliver_B_2147842383_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sliver.B!MTB"
        threat_id = "2147842383"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 20 89 04 24 c7 44 24 08 00 00 00 00 8b 44 24 1c 89 44 24 04 e8 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 89 04 24 c7 44 24 04 00 00 00 00 8b 44 24 1c 89 44 24 08 c7 44 24 0c 00 30 00 00 c7 44 24 10 04 00 00 00 e8 ?? ?? ?? ?? 8b 44 24 14 89 44 24 24 83 c4 18 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ec 20 8d ?? ?? ?? ?? ?? 84 00 8b 05 ?? ?? ?? ?? 8b 4c 24 24 8b 15 ?? ?? ?? ?? 89 04 24 c7 44 24 04 00 00 00 00 c7 44 24 08 00 00 00 00 89 54 24 0c 89 4c 24 10 c7 44 24 14 00 00 00 00 c7 44 24 18 00 00 00 00 e8 ?? ?? ?? ?? 8b 44 24 1c 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {64 8b 0d 14 00 00 00 8b 89 00 00 00 00 3b 61 08 ?? ?? 83 ec 10 8b 4c 24 1c 8d ?? ?? 39 c1 ?? ?? 8b 44 24 18 0f b6 4c 01 ff 84 c9 ?? ?? 8b 0d ?? ?? ?? ?? 89 0c 24 8b 4c 24 14 89 4c 24 04 89 44 24 08 e8 ?? ?? ?? ?? 8b 44 24 0c 89 44 24 24 83 c4 10 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {64 8b 05 14 00 00 00 8b 80 00 00 00 00 8b 40 18 8b 0d ?? ?? ?? ?? 8b 80 cc 01 00 00 89 0c 24 89 44 24 04 c7 44 24 08 ff ff ff ff e8 ?? ?? ?? ?? 8b 44 24 0c e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Sliver_D_2147842384_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sliver.D!MTB"
        threat_id = "2147842384"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ExecuteAssemblyReq)." ascii //weight: 1
        $x_1_2 = "Impersonate)." ascii //weight: 1
        $x_1_3 = "InvokeMigrateReq)." ascii //weight: 1
        $x_1_4 = "DNSPoll)." ascii //weight: 1
        $x_1_5 = "DNSBlockHeader)." ascii //weight: 1
        $x_1_6 = ").Username" ascii //weight: 1
        $x_1_7 = ").Password" ascii //weight: 1
        $x_1_8 = ").Hostname" ascii //weight: 1
        $x_1_9 = ").Port" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Sliver_E_2147842385_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sliver.E!MTB"
        threat_id = "2147842385"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ExecuteAssemblyReq)." ascii //weight: 1
        $x_1_2 = "Impersonate)." ascii //weight: 1
        $x_1_3 = "InvokeMigrateReq)." ascii //weight: 1
        $x_1_4 = "DNSPoll)." ascii //weight: 1
        $x_1_5 = "DNSBlockHeader)." ascii //weight: 1
        $x_1_6 = "Migrate)." ascii //weight: 1
        $x_1_7 = "InvokeGetSystemReq)." ascii //weight: 1
        $x_1_8 = "InvokeSpawnDllReq)." ascii //weight: 1
        $x_1_9 = "SideloadReq)." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

