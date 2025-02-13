rule Ransom_Win32_Mambretor_A_2147717347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mambretor.A"
        threat_id = "2147717347"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mambretor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\DC22\\netpass.exe" ascii //weight: 10
        $x_10_2 = "net user /add mythbusters" ascii //weight: 10
        $x_10_3 = {68 00 64 00 30 00 00 00 73 74 61 72 74 20 68 61 72 64 20 64 72 69 76 65 20 65 6e 63}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mambretor_A_2147717347_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mambretor.A"
        threat_id = "2147717347"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mambretor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "(w889901665@yandex.com)" ascii //weight: 4
        $x_1_2 = "You are Hacked !!!!" ascii //weight: 1
        $x_1_3 = "Your H.D.D Encrypted , Contact Us For Decryption Key" ascii //weight: 1
        $x_2_4 = {59 4f 55 52 49 44 3a 20 31 32 33 [0-16] 00 00 00 00 [0-16] 70 61 73 73 77 6f 72 64 20 69 6e 63 6f 72 72 65 63 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Mambretor_C_2147717878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mambretor.C"
        threat_id = "2147717878"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mambretor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "start hard drive encryption..." ascii //weight: 10
        $x_10_2 = "-boot -setmbr hd0" wide //weight: 10
        $x_10_3 = "\\dccon.exe" wide //weight: 10
        $x_1_4 = "LWVuY3J5cHQgcHQ" ascii //weight: 1
        $x_1_5 = "-encrypt pt" ascii //weight: 1
        $x_1_6 = "ICYgdGFza2tpbGwgL2ltIE1vdW50LmV4ZS" ascii //weight: 1
        $x_1_7 = "& taskkill /im Mount.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Mambretor_E_2147718618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mambretor.E"
        threat_id = "2147718618"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mambretor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Users\\public.Unkonw\\Desktop\\CRP_95_08_30_v3\\CRP\\Release\\Mount.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mambretor_D_2147723055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mambretor.D"
        threat_id = "2147723055"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mambretor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ICYgdGFza2tpbGwgL2ltIE1vdW50LmV4ZS" ascii //weight: 1
        $x_1_2 = "LWVuY3J5cHQgcHQ" ascii //weight: 1
        $x_1_3 = "L0MgcGluZyAxLjEuMS4xIC1uIDEgLXcgMzAwMCA+IE51bCAmIHNjIGRlbGV0ZSBEZWZyYWdtZW50U2VydmljZSAmIERlbCAi" ascii //weight: 1
        $x_1_4 = "XGRjY29uLmV4ZQ" ascii //weight: 1
        $x_1_5 = "%s\\drivers\\%s" wide //weight: 1
        $x_1_6 = "32DCRYPT.SYS" wide //weight: 1
        $x_1_7 = "2C:\\xampp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

