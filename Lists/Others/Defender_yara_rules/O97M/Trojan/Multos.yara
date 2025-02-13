rule Trojan_O97M_Multos_A_2147720557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Multos.A"
        threat_id = "2147720557"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Multos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KQpleGVjKCcnLmpvaW4ob3V0KSk=" ascii //weight: 1
        $x_1_2 = "system Lib \"libc.dylib\"" ascii //weight: 1
        $x_1_3 = "\"import sys,base64;exec(base64.b64decode" ascii //weight: 1
        $x_1_4 = "Sub autoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

