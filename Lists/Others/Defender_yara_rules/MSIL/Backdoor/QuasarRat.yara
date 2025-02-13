rule Backdoor_MSIL_QuasarRat_GG_2147753051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/QuasarRat.GG!MTB"
        threat_id = "2147753051"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Clipboard" ascii //weight: 1
        $x_10_2 = "XData Source=WTFBEE-PC\\SQLEXSERVER" ascii //weight: 10
        $x_1_3 = "select * from QL_NguoiDung where TenDangNhap" ascii //weight: 1
        $x_1_4 = "select name From sys.databases" ascii //weight: 1
        $x_1_5 = "Password=" ascii //weight: 1
        $x_1_6 = "LTWNCConn" ascii //weight: 1
        $x_1_7 = "tinyurl.com" ascii //weight: 1
        $x_1_8 = "api.bit.ly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

