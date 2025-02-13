rule Ransom_MSIL_Zenizozorypt_A_2147726347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Zenizozorypt.A"
        threat_id = "2147726347"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zenizozorypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "<p>I am ZENIS. A mischievous boy who loves cryptography, hardware and programming." wide //weight: 10
        $x_1_2 = "ZenisCryptorService" wide //weight: 1
        $x_1_3 = "/C vssadmin.exe delete shadows /all /Quiet:" wide //weight: 1
        $x_1_4 = "TheZenis@Tutanota.com" wide //weight: 1
        $x_1_5 = "TheZenis@MailFence.com" wide //weight: 1
        $x_1_6 = "TheZenis@Protonmail.com" wide //weight: 1
        $x_1_7 = "\\Zenis-Instructions.html" wide //weight: 1
        $x_1_8 = "<br>%EMAIL0%</br>" wide //weight: 1
        $x_1_9 = "<small hidden>%ENCRYPTED%</small>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

