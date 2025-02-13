rule Ransom_MSIL_Cataka_MA_2147896445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cataka.MA!MTB"
        threat_id = "2147896445"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cataka"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "KILL_APPS_ENCRYPT_AGAIN" ascii //weight: 1
        $x_1_2 = "--- CATAKA RANSOMWARE---" wide //weight: 1
        $x_1_3 = "Oops sorry your file has been encrypted using a very strong algorithm" wide //weight: 1
        $x_1_4 = "It might be impossible to open it without a special key from me" wide //weight: 1
        $x_1_5 = {43 00 6f 00 6e 00 74 00 61 00 63 00 74 00 20 00 65 00 6d 00 61 00 69 00 6c 00 3a 00 20 00 69 00 74 00 73 00 65 00 76 00 69 00 6c 00 63 00 6f 00 72 00 70 00 [0-5] 40 00 68 00 6f 00 74 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_6 = "Readme.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

