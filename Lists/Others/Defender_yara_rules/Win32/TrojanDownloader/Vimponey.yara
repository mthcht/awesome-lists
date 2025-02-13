rule TrojanDownloader_Win32_Vimponey_A_2147623442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vimponey.A"
        threat_id = "2147623442"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vimponey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "Internet Exp1orer.lnk" wide //weight: 8
        $x_1_2 = "ntfs.sys" wide //weight: 1
        $x_1_3 = "bc.sys" wide //weight: 1
        $x_1_4 = "bootsafe.sys" wide //weight: 1
        $x_4_5 = "TTraveler.exe" wide //weight: 4
        $x_5_6 = "ksmgui.exe" wide //weight: 5
        $x_2_7 = "360se.exe" wide //weight: 2
        $x_1_8 = "ntoskrnl.exe" ascii //weight: 1
        $x_3_9 = "\\SystemRoot\\System32\\ntdll.d11" wide //weight: 3
        $x_4_10 = "ekrn.exeegui.exe" wide //weight: 4
        $x_2_11 = "\\REGISTRY\\MACHINE\\SYSTEM\\*\\Root" wide //weight: 2
        $x_2_12 = "\\registry\\user\\*\\Software\\Microsoft\\Internet Explorer\\Main" wide //weight: 2
        $x_2_13 = "\\REGISTRY\\MACHINE\\SYSTEM\\*\\Services" wide //weight: 2
        $x_4_14 = "\\REGISTRY\\MACHINE\\SYSTEM\\*MACPIET" wide //weight: 4
        $x_3_15 = "ZwCreateSection" ascii //weight: 3
        $x_1_16 = "MmMapViewOfSection" ascii //weight: 1
        $x_2_17 = "WriteProcessMemory" ascii //weight: 2
        $x_4_18 = "ZwLoadDriver" ascii //weight: 4
        $x_2_19 = "www.union888.com" ascii //weight: 2
        $x_3_20 = "http://www.kuku530.com/?" wide //weight: 3
        $x_1_21 = "URL=http://www.kuku530.com/?Favorites" ascii //weight: 1
        $x_3_22 = "POST /cc.aspx HTTP/1.0" ascii //weight: 3
        $x_1_23 = "Accept: text/html, money/rmb" ascii //weight: 1
        $x_3_24 = "NTICE" wide //weight: 3
        $x_4_25 = "SYSERBOOT" wide //weight: 4
        $x_3_26 = "ICEEXT" wide //weight: 3
        $x_2_27 = "legacy_" wide //weight: 2
        $x_3_28 = "kernel32.dll|user32.dll|Dnsapi.dll|Ws2_32.dll|PSAPI.DLL|WSOCK32.DLL|shlwapi.dll|wsprintfA|GetModuleBaseNameW|DnsQuery_W|SHGetValueA|SHSetValueA|n1.haode81.com|n2.haode81.com|www.kuku530.com|.kuku530.|.googlesyndication.|eset.|[InternetShortcut]" ascii //weight: 3
        $x_2_29 = "|USERPROFILE|\\Favorites\\" ascii //weight: 2
        $x_1_30 = "HOST: %s" ascii //weight: 1
        $x_1_31 = "ETag: %s" ascii //weight: 1
        $x_1_32 = ".vmp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_4_*) and 7 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_4_*) and 7 of ($x_3_*) and 8 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 4 of ($x_4_*) and 7 of ($x_3_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_8_*) and 5 of ($x_4_*) and 6 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_8_*) and 5 of ($x_4_*) and 6 of ($x_3_*) and 8 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 5 of ($x_4_*) and 7 of ($x_3_*) and 6 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_8_*) and 5 of ($x_4_*) and 7 of ($x_3_*) and 7 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_8_*) and 5 of ($x_4_*) and 7 of ($x_3_*) and 8 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 7 of ($x_3_*) and 7 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 7 of ($x_3_*) and 8 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 4 of ($x_4_*) and 5 of ($x_3_*) and 8 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 4 of ($x_4_*) and 6 of ($x_3_*) and 7 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 4 of ($x_4_*) and 6 of ($x_3_*) and 8 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 4 of ($x_4_*) and 7 of ($x_3_*) and 5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 4 of ($x_4_*) and 7 of ($x_3_*) and 6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 4 of ($x_4_*) and 7 of ($x_3_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 4 of ($x_4_*) and 7 of ($x_3_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 4 of ($x_3_*) and 8 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 5 of ($x_3_*) and 6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 5 of ($x_3_*) and 7 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 5 of ($x_3_*) and 8 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 6 of ($x_3_*) and 5 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 6 of ($x_3_*) and 6 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 6 of ($x_3_*) and 7 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 6 of ($x_3_*) and 8 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 7 of ($x_3_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 7 of ($x_3_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 7 of ($x_3_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 7 of ($x_3_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 7 of ($x_3_*) and 7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 5 of ($x_4_*) and 7 of ($x_3_*) and 8 of ($x_2_*))) or
            (all of ($x*))
        )
}

