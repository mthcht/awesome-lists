rule PWS_MSIL_Chifroms_A_2147638754_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Chifroms.A"
        threat_id = "2147638754"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chifroms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_ChromePass" ascii //weight: 1
        $x_1_2 = "get_iepv" ascii //weight: 1
        $x_1_3 = "get_mspass" ascii //weight: 1
        $x_1_4 = "get_PasswordFox" ascii //weight: 1
        $x_1_5 = "MozillaSteal" ascii //weight: 1
        $x_1_6 = "ChromeSteal" ascii //weight: 1
        $x_1_7 = "IeSteal" ascii //weight: 1
        $x_1_8 = "MailSteal" ascii //weight: 1
        $x_1_9 = "steamsteal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule PWS_MSIL_Chifroms_A_2147638754_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Chifroms.A"
        threat_id = "2147638754"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chifroms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 74 65 61 6d 73 74 65 61 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {67 65 74 5f 57 69 6e 64 6f 77 73 43 44 4b 65 79 50 61 72 74 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {67 65 74 5f 50 61 73 73 77 6f 72 64 46 6f 78 00}  //weight: 1, accuracy: High
        $x_1_4 = {67 65 74 5f 6d 73 70 61 73 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 68 72 6f 6d 65 73 74 65 61 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

