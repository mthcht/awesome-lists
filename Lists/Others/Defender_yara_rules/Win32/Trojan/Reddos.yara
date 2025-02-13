rule Trojan_Win32_Reddos_A_2147605823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reddos.A"
        threat_id = "2147605823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reddos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GET /aux/con/com1/../../[LAG]../.%%%%%%%%./../../../../fakecnn/redflag-stay-here.php.aspx.asp.cfm.jsp HTTP/1.1" ascii //weight: 2
        $x_1_2 = "Powered by [LAG]" ascii //weight: 1
        $x_1_3 = {52 65 64 46 6c 61 67 00 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

