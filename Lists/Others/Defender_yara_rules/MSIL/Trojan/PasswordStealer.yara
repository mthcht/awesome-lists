rule Trojan_MSIL_PasswordStealer_PA_2147752176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PasswordStealer.PA!MTB"
        threat_id = "2147752176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PasswordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "grab_photo_from_desktop" ascii //weight: 1
        $x_1_2 = "grab_docs_from_Document" ascii //weight: 1
        $x_1_3 = "upload_screenshot" ascii //weight: 1
        $x_1_4 = "browser_passwords" ascii //weight: 1
        $x_1_5 = "emails_pass" ascii //weight: 1
        $x_1_6 = "upload_passwords" ascii //weight: 1
        $x_1_7 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_1_8 = "IMAP Password" wide //weight: 1
        $x_1_9 = "POP3 Password" wide //weight: 1
        $x_1_10 = "credit_cards" wide //weight: 1
        $x_1_11 = "Card Number" wide //weight: 1
        $x_1_12 = "Graber From" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

