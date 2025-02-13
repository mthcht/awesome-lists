rule Trojan_Win64_BumbleBeeLoader_AG_2147819249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBeeLoader.AG!MSR"
        threat_id = "2147819249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBeeLoader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Eei15i" ascii //weight: 2
        $x_2_2 = "LiRNN5F" ascii //weight: 2
        $x_2_3 = "XZrEX92261" ascii //weight: 2
        $x_1_4 = "romantic lofty legitimate distract" ascii //weight: 1
        $x_1_5 = "CallNamedPipeA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBeeLoader_AG_2147819249_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBeeLoader.AG!MSR"
        threat_id = "2147819249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBeeLoader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CHhDJCN" ascii //weight: 2
        $x_2_2 = "DwDDBS65m" ascii //weight: 2
        $x_2_3 = "HlLcu988" ascii //weight: 2
        $x_2_4 = "PRi16SE" ascii //weight: 2
        $x_2_5 = "RWHwy6R" ascii //weight: 2
        $x_1_6 = "political debris yell could quiver" ascii //weight: 1
        $x_1_7 = "CreateNamedPipeA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBeeLoader_AG_2147819249_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBeeLoader.AG!MSR"
        threat_id = "2147819249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBeeLoader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DHFXCM9Pq" ascii //weight: 2
        $x_2_2 = "LftYk" ascii //weight: 2
        $x_2_3 = "QBSijpzw" ascii //weight: 2
        $x_2_4 = "SixO5071D" ascii //weight: 2
        $x_2_5 = "UqC80" ascii //weight: 2
        $x_1_6 = "touch haze hanky sculpture sanction rag hopes" ascii //weight: 1
        $x_1_7 = "ConnectNamedPipe" ascii //weight: 1
        $x_1_8 = "GetStartupInfoW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_BumbleBeeLoader_AG_2147819249_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBeeLoader.AG!MSR"
        threat_id = "2147819249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBeeLoader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HPsbB564U" ascii //weight: 2
        $x_2_2 = "UDIOcO810q3Y" ascii //weight: 2
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "cleanup spot bodily fulfil grabbed rabbit" ascii //weight: 1
        $x_1_5 = "CreateNamedPipeA" ascii //weight: 1
        $x_1_6 = "PeekNamedPipe" ascii //weight: 1
        $x_1_7 = "GetCurrentDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBeeLoader_AG_2147819249_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBeeLoader.AG!MSR"
        threat_id = "2147819249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBeeLoader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KInMQF" ascii //weight: 2
        $x_2_2 = "KwNqBn2l9N" ascii //weight: 2
        $x_2_3 = "SrNF6Da" ascii //weight: 2
        $x_2_4 = "DllRegisterServer" ascii //weight: 2
        $x_1_5 = "business overlook dungeon feral fowls spiders rate frosty" ascii //weight: 1
        $x_1_6 = "ConnectNamedPipe" ascii //weight: 1
        $x_1_7 = "GetStartupInfoW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBeeLoader_AG_2147819249_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBeeLoader.AG!MSR"
        threat_id = "2147819249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBeeLoader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DduBHO" ascii //weight: 2
        $x_2_2 = "FxQuirL2" ascii //weight: 2
        $x_2_3 = "KNKmtthIo" ascii //weight: 2
        $x_2_4 = "KsmT27Y" ascii //weight: 2
        $x_2_5 = "ZWfODA64" ascii //weight: 2
        $x_2_6 = "DllRegisterServer" ascii //weight: 2
        $x_1_7 = "hardworking facing concentration South amber been safety forbes" ascii //weight: 1
        $x_1_8 = "CallNamedPipeA" ascii //weight: 1
        $x_1_9 = "GetStartupInfoW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBeeLoader_AG_2147819249_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBeeLoader.AG!MSR"
        threat_id = "2147819249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBeeLoader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MYtl2K" ascii //weight: 1
        $x_1_2 = "UybzwGr" ascii //weight: 1
        $x_1_3 = "YCNENP" ascii //weight: 1
        $x_1_4 = "ghjgkadsfgdjgh" ascii //weight: 1
        $x_1_5 = "ivYiw2" ascii //weight: 1
        $x_1_6 = "liBEFa3Qqb" ascii //weight: 1
        $x_1_7 = "rBn1NyOsnB" ascii //weight: 1
        $x_1_8 = "tLEmYa8" ascii //weight: 1
        $x_1_9 = "xhphnS" ascii //weight: 1
        $x_1_10 = "ywwpkC" ascii //weight: 1
        $x_1_11 = "f21ba205858645ace1ac3dc8425bb0adee8dc7c8f7c410081c7aacf7ce363a75c37e352f4c0a83dd9dbca871c7dce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBeeLoader_AG_2147819249_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBeeLoader.AG!MSR"
        threat_id = "2147819249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBeeLoader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KInMQF" ascii //weight: 1
        $x_1_2 = "KwNqBn2l9N" ascii //weight: 1
        $x_1_3 = "SrNF6Da" ascii //weight: 1
        $x_1_4 = "LLBMPMUsqf" ascii //weight: 1
        $x_1_5 = "ConnectNamedPipe" ascii //weight: 1
        $x_1_6 = "CreateNamedPipeA" ascii //weight: 1
        $x_1_7 = "WaitNamedPipeA" ascii //weight: 1
        $x_1_8 = "GetCurrentActCtx" ascii //weight: 1
        $x_1_9 = "fowls spiders rate frosty covering brutally numerals waving huge wedge broadcasting fill cow faithful intelligent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBeeLoader_AG_2147819249_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBeeLoader.AG!MSR"
        threat_id = "2147819249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBeeLoader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MDbJvVaNCR" ascii //weight: 1
        $x_1_2 = "GetProcessHeap" ascii //weight: 1
        $x_1_3 = "GetStartupInfoW" ascii //weight: 1
        $x_1_4 = "InitializeCriticalSection" ascii //weight: 1
        $x_1_5 = "EnterCriticalSection" ascii //weight: 1
        $x_1_6 = "LeaveCriticalSection" ascii //weight: 1
        $x_2_7 = "dough shindy ralph brushed wolf behalf answered city reared recruit sufficiently constellation ski surplus rely foggy sparrow oyster pursuit interval Bible" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBeeLoader_AG_2147819249_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBeeLoader.AG!MSR"
        threat_id = "2147819249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBeeLoader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "TXI073Byz" ascii //weight: 3
        $x_3_2 = "EdHVntqdWt" ascii //weight: 3
        $x_1_3 = "PeekNamedPipe" ascii //weight: 1
        $x_1_4 = "CreateNamedPipeA" ascii //weight: 1
        $x_1_5 = "GetComputerNameA" ascii //weight: 1
        $x_1_6 = "GetStartupInfoW" ascii //weight: 1
        $x_1_7 = "EnterCriticalSection" ascii //weight: 1
        $x_1_8 = "DeleteCriticalSection" ascii //weight: 1
        $x_1_9 = "GetProcAddress" ascii //weight: 1
        $x_1_10 = "LoadLibraryExW" ascii //weight: 1
        $x_1_11 = "GetCurrentProcess" ascii //weight: 1
        $x_1_12 = "TerminateProcess" ascii //weight: 1
        $x_1_13 = "GetEnvironmentStringsW" ascii //weight: 1
        $x_1_14 = "WriteFile" ascii //weight: 1
        $x_1_15 = "GetProcessHeap" ascii //weight: 1
        $x_1_16 = "HeapAlloc" ascii //weight: 1
        $x_1_17 = "GetModuleFileNameA" ascii //weight: 1
        $x_1_18 = "CreateFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBeeLoader_SFDB_2147925458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBeeLoader.SFDB!MTB"
        threat_id = "2147925458"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBeeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FbGIN678" ascii //weight: 2
        $x_1_2 = "enmy555xo79.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

