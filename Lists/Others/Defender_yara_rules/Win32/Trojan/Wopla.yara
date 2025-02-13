rule Trojan_Win32_Wopla_Y_2147582704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wopla.gen!Y"
        threat_id = "2147582704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wopla"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "234"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CreateFileA" ascii //weight: 10
        $x_10_2 = "GetSystemDirectoryA" ascii //weight: 10
        $x_10_3 = "WriteFile" ascii //weight: 10
        $x_10_4 = "CreateProcessA" ascii //weight: 10
        $x_10_5 = "GetFileSize" ascii //weight: 10
        $x_10_6 = "CreateThread" ascii //weight: 10
        $x_10_7 = "CreateMutexA" ascii //weight: 10
        $x_10_8 = "GetStartupInfoA" ascii //weight: 10
        $x_10_9 = "AdjustTokenPrivileges" ascii //weight: 10
        $x_10_10 = "LookupPrivilegeValueA" ascii //weight: 10
        $x_10_11 = "FtpPutFileA" ascii //weight: 10
        $x_10_12 = "InternetConnectA" ascii //weight: 10
        $x_10_13 = "InternetOpenA" ascii //weight: 10
        $x_10_14 = "InternetReadFile" ascii //weight: 10
        $x_10_15 = "InternetOpenUrlA" ascii //weight: 10
        $x_10_16 = "IsUserAdmin" ascii //weight: 10
        $x_10_17 = "setupapi.dll" ascii //weight: 10
        $x_10_18 = "Content-Type: multipart/mixed; boundary=\"----------%s\"" ascii //weight: 10
        $x_10_19 = "%sSubject: %08X_%08X" ascii //weight: 10
        $x_10_20 = "%sTo: %s" ascii //weight: 10
        $x_10_21 = "From: <%s>" ascii //weight: 10
        $x_10_22 = "Date: %a, %d %b %Y %H:%M:%S" ascii //weight: 10
        $x_10_23 = "Placeholder_Data" ascii //weight: 10
        $x_1_24 = ".nulladdress.com" ascii //weight: 1
        $x_1_25 = ".secdep.info" ascii //weight: 1
        $x_1_26 = "st_log.dat" ascii //weight: 1
        $x_1_27 = "sm_log.dat" ascii //weight: 1
        $x_1_28 = "sc_log.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((23 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

