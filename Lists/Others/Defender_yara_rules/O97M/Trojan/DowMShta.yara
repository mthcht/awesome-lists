rule Trojan_O97M_DowMShta_A_2147810989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/DowMShta.A"
        threat_id = "2147810989"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "DowMShta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd /c m^sh^t^a h^tt^p^:/^/" ascii //weight: 10
        $x_10_2 = "cmd /c ms^h^ta ht^tp:/^/" ascii //weight: 10
        $x_10_3 = "start ms^h^ta ht^tp:/^/" ascii //weight: 10
        $x_10_4 = "mshta http://0xb907d607/" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_O97M_DowMShta_B_2147811205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/DowMShta.B"
        threat_id = "2147811205"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "DowMShta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd /c ms^" ascii //weight: 10
        $x_10_2 = "cmd /c m^" ascii //weight: 10
        $x_10_3 = "start ms^" ascii //weight: 10
        $x_10_4 = "start m^" ascii //weight: 10
        $n_100_5 = "start mshta" ascii //weight: -100
        $n_100_6 = "cmd /c mshta" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

