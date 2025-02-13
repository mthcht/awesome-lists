rule Ransom_MSIL_WannaDieCrypt_PA_2147784001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaDieCrypt.PA!MTB"
        threat_id = "2147784001"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaDieCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft System.exe" ascii //weight: 1
        $x_1_2 = "Your PC is now encrypted!" wide //weight: 1
        $x_1_3 = "Your PC is now infected with WannaDie ransomware" wide //weight: 1
        $x_1_4 = "WannaDie-ID-234153" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

