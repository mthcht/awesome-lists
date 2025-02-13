rule Ransom_MSIL_Noobcrypt_A_2147717279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Noobcrypt.A"
        threat_id = "2147717279"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noobcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "midomsamar1@gmail.com" wide //weight: 1
        $x_1_2 = "booter-service@hotmail.com" wide //weight: 1
        $x_1_3 = "In order to unlock && decrypt your PC you MUST pay  $200 in the address down below" wide //weight: 1
        $x_1_4 = "payment.moj88w62BXxu96R0W762H0748s8q91YB43O165Sa3fN1274kJ28UX4.restaurantintim.ro" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

