rule Ransom_MSIL_Mtroska_ST_2147762163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Mtroska.ST!MTB"
        threat_id = "2147762163"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mtroska"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".HUSTONWEHAVEAPROBLEM@KEEMAIL.ME" ascii //weight: 1
        $x_1_2 = "HOW_TO_RECOVER_ENCRYPTED_FILES" ascii //weight: 1
        $x_1_3 = "/C choice /C Y /N /D Y /T 3 & Del" ascii //weight: 1
        $x_1_4 = "checkip.dyndns.org" ascii //weight: 1
        $x_1_5 = "YOUR FILES ARE ENCRYPTED!" ascii //weight: 1
        $x_1_6 = "After payment we will send you the decryption tool that will decrypt all your files." ascii //weight: 1
        $x_1_7 = "Do not try to decrypt your data using third party software, it may cause permanent data loss." ascii //weight: 1
        $x_1_8 = "Attempts to self-decrypting files will result in the loss of your data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

