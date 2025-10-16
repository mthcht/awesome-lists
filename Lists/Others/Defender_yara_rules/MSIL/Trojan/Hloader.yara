rule Trojan_MSIL_Hloader_A_2147955258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hloader.A"
        threat_id = "2147955258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZW5jcnlwdG9B" ascii //weight: 1
        $x_1_2 = "ZXh0cmFjdEFB" ascii //weight: 1
        $x_1_3 = "a2V5QUFB" ascii //weight: 1
        $x_1_4 = "RG9Xb3JrQUFB" ascii //weight: 1
        $x_1_5 = "R3VuemlwQUFB" ascii //weight: 1
        $x_1_6 = "WG9yQUFB" ascii //weight: 1
        $x_1_7 = "cGFzc3dvcmRB" ascii //weight: 1
        $x_1_8 = {59 5f 0c 02 07 02 07 91 06 08 91 61 d2 9c 07 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

