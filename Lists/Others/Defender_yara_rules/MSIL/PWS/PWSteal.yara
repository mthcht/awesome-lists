rule PWS_MSIL_PWSteal_A_2147726141_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/PWSteal.A!bit"
        threat_id = "2147726141"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PWSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://inseltech.com.mx/t1/lala.php" wide //weight: 1
        $x_1_2 = "http://ggl.com" wide //weight: 1
        $x_1_3 = {47 65 74 4f 75 74 6c 6f 6f 6b 50 61 73 73 77 6f 72 64 73 00 64 65 63 72 79 70 74 4f 75 74 6c 6f 6f 6b 50 61 73 73 77 6f 72 64}  //weight: 1, accuracy: High
        $x_1_4 = "SMTP Server" wide //weight: 1
        $x_1_5 = "POP3 Password" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook" wide //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

