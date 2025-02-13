rule Ransom_MSIL_TapPiF_PA_2147762523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/TapPiF.PA!MTB"
        threat_id = "2147762523"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TapPiF"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Ooops! Your Some Files Has Been Encrypted!" ascii //weight: 1
        $x_1_2 = "Your Computer has been injected by TapRiF Trojans!" ascii //weight: 1
        $x_1_3 = "2478290.bat" ascii //weight: 1
        $x_1_4 = "Pay Now, If You Wanna to Decrypt Your all files!" ascii //weight: 1
        $x_1_5 = {5c 00 54 00 61 00 70 00 50 00 69 00 46 00 5c 00 6f 00 62 00 6a 00 5c 00 [0-16] 5c 00 54 00 61 00 70 00 50 00 69 00 46 00 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 54 61 70 50 69 46 5c 6f 62 6a 5c [0-16] 5c 54 61 70 50 69 46 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

