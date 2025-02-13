rule Trojan_Win32_SuspGolang_MK_2147913295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspGolang.MK"
        threat_id = "2147913295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspGolang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ").Password" ascii //weight: 1
        $x_1_2 = ").Hostname" ascii //weight: 1
        $x_1_3 = ").Port" ascii //weight: 1
        $x_1_4 = "ExecuteAssemblyReq)." ascii //weight: 1
        $x_1_5 = "Impersonate)." ascii //weight: 1
        $x_1_6 = "InvokeMigrateReq)." ascii //weight: 1
        $x_1_7 = "DNSPoll)." ascii //weight: 1
        $x_1_8 = "DNSBlockHeader)." ascii //weight: 1
        $x_1_9 = ").Username" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspGolang_MG_2147913297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspGolang.MG"
        threat_id = "2147913297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspGolang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Migrate)." ascii //weight: 1
        $x_1_2 = "InvokeGetSystemReq)." ascii //weight: 1
        $x_1_3 = "InvokeSpawnDllReq)." ascii //weight: 1
        $x_1_4 = "SideloadReq)." ascii //weight: 1
        $x_1_5 = "ExecuteAssemblyReq)." ascii //weight: 1
        $x_1_6 = "Impersonate)." ascii //weight: 1
        $x_1_7 = "InvokeMigrateReq)." ascii //weight: 1
        $x_1_8 = "DNSPoll)." ascii //weight: 1
        $x_1_9 = "DNSBlockHeader)." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspGolang_NK_2147914565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspGolang.NK"
        threat_id = "2147914565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspGolang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ").AffirmLogin" ascii //weight: 1
        $x_1_2 = ").LoadOrStore" ascii //weight: 1
        $x_1_3 = ").GetUserProfileDirectory" ascii //weight: 1
        $x_1_4 = ").LoadAndDelete" ascii //weight: 1
        $x_1_5 = ").CompareAndDelete" ascii //weight: 1
        $x_1_6 = ").TryLock" ascii //weight: 1
        $x_1_7 = ").Nanoseconds" ascii //weight: 1
        $x_1_8 = ").GetTokenPrimaryGroup" ascii //weight: 1
        $x_1_9 = ").GetTokenUser" ascii //weight: 1
        $x_1_10 = "InvokeInProcExecuteAssemblyReq)." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspGolang_GK_2147914566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspGolang.GK"
        threat_id = "2147914566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspGolang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MemfilesAddReq)." ascii //weight: 1
        $x_1_2 = "MemfilesAdd)." ascii //weight: 1
        $x_1_3 = "MemfilesRmReq)." ascii //weight: 1
        $x_1_4 = "MemfilesRm)." ascii //weight: 1
        $x_1_5 = "SockTabEntry_SockAddr)." ascii //weight: 1
        $x_1_6 = "PivotType)." ascii //weight: 1
        $x_1_7 = "PeerFailureType)." ascii //weight: 1
        $x_1_8 = ").DeleteTun" ascii //weight: 1
        $x_1_9 = ").DeleteSeq" ascii //weight: 1
        $x_1_10 = ").VarTimeDoubleScalarBaseMult" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspGolang_LK_2147914567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspGolang.LK"
        threat_id = "2147914567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspGolang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RportFwdStopListenerReq)." ascii //weight: 1
        $x_1_2 = "RportFwdStartListenerReq)." ascii //weight: 1
        $x_1_3 = "RportFwdListener)." ascii //weight: 1
        $x_1_4 = "RportFwdListeners)." ascii //weight: 1
        $x_1_5 = "RportFwdListenersReq)." ascii //weight: 1
        $x_1_6 = "RPortfwd)." ascii //weight: 1
        $x_1_7 = "RPortfwdReq)." ascii //weight: 1
        $x_1_8 = "ChmodReq)." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspGolang_QK_2147914568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspGolang.QK"
        threat_id = "2147914568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspGolang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UUID).UnmarshalBinary" ascii //weight: 1
        $x_1_2 = "Chmod)." ascii //weight: 1
        $x_1_3 = "ChownReq)." ascii //weight: 1
        $x_1_4 = ").SetWriteDeadline" ascii //weight: 1
        $x_1_5 = "Chown)." ascii //weight: 1
        $x_1_6 = "ChtimesReq)." ascii //weight: 1
        $x_1_7 = "CurrentTokenOwnerReq)." ascii //weight: 1
        $x_1_8 = "Chtimes)." ascii //weight: 1
        $x_1_9 = "MemfilesListReq)." ascii //weight: 1
        $x_1_10 = "MemfilesAddReq)." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspGolang_AM_2147915792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspGolang.AM"
        threat_id = "2147915792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspGolang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetPrivsReq)." ascii //weight: 1
        $x_1_2 = "WindowsPrivilegeEntry)." ascii //weight: 1
        $x_1_3 = "GetPrivs)." ascii //weight: 1
        $x_1_4 = "PivotStartListenerReq)." ascii //weight: 1
        $x_1_5 = "PivotStopListenerReq)." ascii //weight: 1
        $x_1_6 = ").XORKeyStream" ascii //weight: 1
        $x_1_7 = ").DecryptEncPart" ascii //weight: 1
        $x_1_8 = ").GetKeySeedBitLength" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspGolang_MA_2147915793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspGolang.MA"
        threat_id = "2147915793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspGolang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".MiniDumpIOCallback" ascii //weight: 1
        $x_1_2 = ".MiniDumpCallbackInput" ascii //weight: 1
        $x_1_3 = ").ToProtobuf" ascii //weight: 1
        $x_1_4 = "DNSBlockHeader)." ascii //weight: 1
        $x_1_5 = "HTTPSessionInit)." ascii //weight: 1
        $x_1_6 = "ScreenshotReq)." ascii //weight: 1
        $x_1_7 = "Screenshot)." ascii //weight: 1
        $x_1_8 = "StartServiceReq)." ascii //weight: 1
        $x_1_9 = "ServiceInfo)." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspGolang_AG_2147915794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspGolang.AG"
        threat_id = "2147915794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspGolang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WGSocksStopReq)." ascii //weight: 1
        $x_1_2 = "WGTCPForwardersReq)." ascii //weight: 1
        $x_1_3 = "WGSocksServersReq)." ascii //weight: 1
        $x_1_4 = "WGTCPForwarder)." ascii //weight: 1
        $x_1_5 = "ServiceInfoReq)." ascii //weight: 1
        $x_1_6 = "StopServiceReq)." ascii //weight: 1
        $x_1_7 = "RemoveServiceReq)." ascii //weight: 1
        $x_1_8 = "BackdoorReq)." ascii //weight: 1
        $x_1_9 = ").SetUniformBytes" ascii //weight: 1
        $x_1_10 = ").SetCanonicalBytes" ascii //weight: 1
        $x_1_11 = ").SetBytesWithClamping" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspGolang_LY_2147915795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspGolang.LY"
        threat_id = "2147915795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspGolang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WGSocksServer)." ascii //weight: 1
        $x_1_2 = "WGSocksServers)." ascii //weight: 1
        $x_1_3 = "WGTCPForwarders)." ascii //weight: 1
        $x_1_4 = "ReconfigureReq)." ascii //weight: 1
        $x_1_5 = "Reconfigure)." ascii //weight: 1
        $x_1_6 = "PollIntervalReq)." ascii //weight: 1
        $x_1_7 = ").LocalAddr" ascii //weight: 1
        $x_1_8 = ").RemoteAddr" ascii //weight: 1
        $x_1_9 = ").SetDeadline" ascii //weight: 1
        $x_1_10 = ").SetReadDeadline" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspGolang_Y_2147915796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspGolang.Y"
        threat_id = "2147915796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspGolang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PollInterval)." ascii //weight: 1
        $x_1_2 = "SSHCommandReq)." ascii //weight: 1
        $x_1_3 = "RegisterExtensionReq)." ascii //weight: 1
        $x_1_4 = "RegisterExtension)." ascii //weight: 1
        $x_1_5 = "CallExtensionReq)." ascii //weight: 1
        $x_1_6 = "ListExtensionsReq)." ascii //weight: 1
        $x_1_7 = "DNSSessionInit)." ascii //weight: 1
        $x_1_8 = "ProcessDumpReq)." ascii //weight: 1
        $x_1_9 = ").GetKpasswdServers" ascii //weight: 1
        $x_1_10 = ").WithPassword" ascii //weight: 1
        $x_1_11 = ").HasPassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_SuspGolang_MN_2147915797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspGolang.MN"
        threat_id = "2147915797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspGolang"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Migrate)." ascii //weight: 1
        $x_1_2 = "InvokeGetSystemReq)." ascii //weight: 1
        $x_1_3 = "InvokeSpawnDllReq)." ascii //weight: 1
        $x_1_4 = "SideloadReq)." ascii //weight: 1
        $x_1_5 = "ExecuteAssemblyReq)." ascii //weight: 1
        $x_1_6 = "Impersonate)." ascii //weight: 1
        $x_1_7 = "InvokeMigrateReq)." ascii //weight: 1
        $x_1_8 = ").Password" ascii //weight: 1
        $x_1_9 = ").Hostname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

