rule Trojan_Win32_Collti_A_2147660566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Collti.A"
        threat_id = "2147660566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Collti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "insert into cookies(creation_utc,host_key,name,value,path,expires_utc,secure,httponly,last_access_utc)" wide //weight: 5
        $x_5_2 = "'.sdo.com','sdo_beacon_id','%s','/',%I64d,0,0,%I64d)" wide //weight: 5
        $x_5_3 = ".xiaochencc.com/" wide //weight: 5
        $x_5_4 = "begin_report_system_task" wide //weight: 5
        $x_1_5 = "&mainboardname=" wide //weight: 1
        $x_1_6 = "start_collect" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

