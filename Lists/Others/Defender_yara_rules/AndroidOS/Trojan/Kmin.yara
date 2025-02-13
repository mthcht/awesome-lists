rule Trojan_AndroidOS_Kmin_A_2147650803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Kmin.A"
        threat_id = "2147650803"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Kmin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 75 2e 35 6b 33 67 2e 63 6f 6d 2f 70 6f 72 74 61 6c 2f 6d 2f 63 35 2f ?? 2e 61 73 68 78}  //weight: 1, accuracy: Low
        $x_1_2 = "km/tool/Connect" ascii //weight: 1
        $x_1_3 = "km/launcher/AddAdapter$CreateLiveFolderAction" ascii //weight: 1
        $x_1_4 = "km/charge/HttpBox" ascii //weight: 1
        $x_1_5 = "BbxChargeEngine" ascii //weight: 1
        $x_1_6 = "km/ChargeEngine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Kmin_B_2147657312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Kmin.B"
        threat_id = "2147657312"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Kmin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Service.aspx?ac=getreceiver" ascii //weight: 1
        $x_1_2 = "%service.aspx?ac=getsmsanswer&content=" ascii //weight: 1
        $x_1_3 = {73 75 2e 35 6b 33 67 2e 63 6f 6d 2f 70 6f 72 74 61 6c 2f 6d 2f 63 35 2f ?? 2e 61 73 68 78}  //weight: 1, accuracy: Low
        $x_1_4 = "com.jx.ad.ADService.Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Kmin_C_2147657313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Kmin.C"
        threat_id = "2147657313"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Kmin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6d 2e 6b 6d 2e 6c 61 75 6e 63 68 65 72 [0-1] 2e 73 65 74 74 69 6e 67 73}  //weight: 1, accuracy: Low
        $x_1_2 = "su.5k3g.com" ascii //weight: 1
        $x_1_3 = "portal/m/c6/0.ashx?" ascii //weight: 1
        $x_1_4 = "sdcard/KMInstall/" ascii //weight: 1
        $x_1_5 = "km/charge/HttpBox" ascii //weight: 1
        $x_1_6 = "BbxChargeEngine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

