rule Backdoor_Win32_Sacto_A_2147696329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sacto.A!dha"
        threat_id = "2147696329"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sacto"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\SslMM" ascii //weight: 2
        $x_2_2 = {00 53 53 4c 4d 4d 00}  //weight: 2, accuracy: High
        $x_2_3 = "connect suc begin recv" ascii //weight: 2
        $x_5_4 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/20100719 Firefox/1.0.7" ascii //weight: 5
        $x_5_5 = "\\Office Start.lnk" wide //weight: 5
        $x_5_6 = "POST http://%ws:%d/%d%s%dHTTP/1.1" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Sacto_B_2147718978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sacto.B!dha"
        threat_id = "2147718978"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sacto"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "systen&cp=%s&log=%s&index=%d" wide //weight: 5
        $x_1_2 = "Microsoft Internet Explorer (compatible; MSIE 6.0; Windows NT 5.0)" ascii //weight: 1
        $x_5_3 = "index.asp=%s&ur=%s&cp=%s&os=%s&" wide //weight: 5
        $x_1_4 = "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 5.0)" ascii //weight: 1
        $x_5_5 = "\\Windows Update.lnk" ascii //weight: 5
        $x_2_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Sacto_C_2147718979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sacto.C!dha"
        threat_id = "2147718979"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sacto"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 5.0)" wide //weight: 1
        $x_2_2 = "\\Office Start.lnk" wide //weight: 2
        $x_2_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" wide //weight: 2
        $x_2_4 = {57 69 6e 69 6e 65 74 4d 4d 00}  //weight: 2, accuracy: High
        $x_2_5 = "/%d%s%d" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Sacto_D_2147718980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sacto.D!dha"
        threat_id = "2147718980"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sacto"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/4.0 (compatible; MSIE 6.0;Windows NT 5.0; .NET CLR 1.1.4322)" wide //weight: 1
        $x_2_2 = "\\MSN Talk Start.lnk" wide //weight: 2
        $x_2_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" wide //weight: 2
        $x_2_4 = {57 69 6e 4d 4d 00}  //weight: 2, accuracy: High
        $x_2_5 = "/%d%s%d" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

