rule Trojan_Win32_Biadnex_2147729654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Biadnex"
        threat_id = "2147729654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Biadnex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 3a 5c 57 6f 72 6b 5c 50 72 6f 6a 65 63 74 5c 56 53 5c 68 6f 75 73 65 5c 41 70 70 6c 65 5c 41 70 70 6c 65 5f 32 30 31 38 30 31 31 35 5c 52 65 6c 65 61 73 65 5c 49 6e 73 74 61 6c 6c 43 6c 69 65 6e 74 2e 70 64 62 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "egsvr32.exe \"/u bitsadmin" ascii //weight: 1
        $x_1_3 = "/canceft\\windows\\currebitsadmin /addfibitsadmin /Resumbitsadmin" ascii //weight: 1
        $x_1_4 = "/SetNosoftware\\microsotifyCmdLine %s rle %s" ascii //weight: 1
        $x_1_5 = "itsadmin /creat\\system32\\net.ex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

