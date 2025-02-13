rule Backdoor_Win32_Duetag_A_2147694150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Duetag.A"
        threat_id = "2147694150"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Duetag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://getp.jujutang.com" ascii //weight: 1
        $x_1_2 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;.NET CLR 2.0.50727; .NET4.0C; .NET4.0E" ascii //weight: 1
        $x_1_3 = "cc.tmp" ascii //weight: 1
        $x_1_4 = "m_pTcpAcceptCon" ascii //weight: 1
        $x_1_5 = "%s\\config.dat" ascii //weight: 1
        $x_1_6 = {00 55 64 70 53 65 6e 64 3a 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 44 6f 43 6c 69 65 6e 74 54 61 73 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

