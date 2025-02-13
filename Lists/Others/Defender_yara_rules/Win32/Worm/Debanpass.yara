rule Worm_Win32_Debanpass_A_2147604728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Debanpass.A"
        threat_id = "2147604728"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Debanpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "518"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "D:\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 100
        $x_100_2 = "DoITPayPal" ascii //weight: 100
        $x_100_3 = "[Autorun]" wide //weight: 100
        $x_100_4 = "EBAY - SIGN IN" wide //weight: 100
        $x_100_5 = "c:\\tmpsss.log" wide //weight: 100
        $x_1_6 = "Windows Updata" ascii //weight: 1
        $x_1_7 = "whereAmI" ascii //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_9 = "ShellExecuteA" ascii //weight: 1
        $x_1_10 = "autoRun" ascii //weight: 1
        $x_1_11 = "Encrypt" ascii //weight: 1
        $x_1_12 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_13 = "\\\\.\\SMARTVSD" ascii //weight: 1
        $x_1_14 = "Explorer_Server" wide //weight: 1
        $x_1_15 = "?gift=" wide //weight: 1
        $x_1_16 = "del a.bat" wide //weight: 1
        $x_1_17 = ": selfkill" wide //weight: 1
        $x_1_18 = "attrib -a -r -s -h " wide //weight: 1
        $x_1_19 = "login_email" wide //weight: 1
        $x_1_20 = "login_password" wide //weight: 1
        $x_1_21 = "Accept-Language: zh-cn" wide //weight: 1
        $x_1_22 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Maxthon; .NET CLR 1.1.4322)" wide //weight: 1
        $x_1_23 = "open=" wide //weight: 1
        $x_1_24 = "Microsoft(R) Windows(R) Operating System" wide //weight: 1
        $x_1_25 = "Vista" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_100_*) and 18 of ($x_1_*))) or
            (all of ($x*))
        )
}

