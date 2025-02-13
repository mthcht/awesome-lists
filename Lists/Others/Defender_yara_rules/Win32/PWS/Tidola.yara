rule PWS_Win32_Tidola_A_2147617687_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tidola.A"
        threat_id = "2147617687"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tidola"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "87"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "FindResourceA" ascii //weight: 10
        $x_10_2 = "ServiceDll" ascii //weight: 10
        $x_10_3 = "ReleaseMutex" ascii //weight: 10
        $x_10_4 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 10
        $x_10_5 = "sfc_os.dll" ascii //weight: 10
        $x_10_6 = "dllcache\\rpcss.dll" ascii //weight: 10
        $x_10_7 = "..\\ServicePackFiles\\i386\\rpcss.dll" ascii //weight: 10
        $x_10_8 = "rpcss.dll" ascii //weight: 10
        $x_1_9 = {65 78 70 6c 7e 24 [0-2] 6f 72 65 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_10 = "/post.asp" ascii //weight: 1
        $x_1_11 = "/mibao.asp" ascii //weight: 1
        $x_1_12 = "spcss.dll" ascii //weight: 1
        $x_1_13 = "csrss.dll" ascii //weight: 1
        $x_1_14 = "rss.exeEvent" ascii //weight: 1
        $x_1_15 = {2e 61 64 64 00}  //weight: 1, accuracy: High
        $x_1_16 = "csrss.exeMutex" ascii //weight: 1
        $x_1_17 = "%s%02x*.dll" ascii //weight: 1
        $x_1_18 = "spcss.GetRPCSSInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tidola_A_2147620359_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tidola.A!dll"
        threat_id = "2147620359"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tidola"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pa~$ssport.yuyan.com" ascii //weight: 1
        $x_1_2 = {2e 61 64 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 61 6d 65 3d [0-3] 26 70 61 72 61 3d 25 73 26 25 76 65 73 3d [0-3] 26 64 31 30 3d 25 73 26 64 31 31 3d 25 73 26 64 30 30 3d 25 73 26 64 30 31 3d 25 73 26 64 32 30 3d 25 73 3a 25 73 25 25 32 30 25 73 3a 25 73 25 25 32 30 25 73 3a 25 73 26 64 37 30 3d 25 64 26 64 39 30 3d 25 64}  //weight: 1, accuracy: Low
        $x_1_4 = "act=&d10=%s&d80=%d" ascii //weight: 1
        $x_1_5 = "http://%s:%d%s?%s" ascii //weight: 1
        $x_1_6 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_7 = "%s%s%x" ascii //weight: 1
        $x_1_8 = "%s%s*.dll" ascii //weight: 1
        $x_1_9 = "csrss.exe" ascii //weight: 1
        $n_100_10 = "CrossLinkSVC" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (8 of ($x*))
}

