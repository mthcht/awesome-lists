rule Trojan_Win32_SusTempExec_MK_2147947974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusTempExec.MK"
        threat_id = "2147947974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusTempExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wscript" wide //weight: 1
        $x_1_2 = "appdata\\local\\temp" wide //weight: 1
        $x_1_3 = "bdata.vbs //b" wide //weight: 1
        $x_1_4 = {5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-96] 2e 00 74 00 78 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 74 65 6d 70 5c [0-96] 2e 74 78 74 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = "phonehome_main " ascii //weight: 1
        $x_1_7 = "\\\\.\\pipe\\move" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

