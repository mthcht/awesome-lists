rule Trojan_MSIL_Blinerarch_A_2147681038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blinerarch.A"
        threat_id = "2147681038"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blinerarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<option>fuck ie!</option>" wide //weight: 1
        $x_1_2 = "http://77.221.149.219" wide //weight: 1
        $x_1_3 = "html@asdasd.ru" wide //weight: 1
        $x_1_4 = "jQuery(function($){$('#za_phone').mask(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blinerarch_AT_2147681051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blinerarch.AT"
        threat_id = "2147681051"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blinerarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 73 6d 73 5f 70 61 74 74 65 72 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 65 6e 64 53 4d 53 00}  //weight: 1, accuracy: High
        $x_1_3 = "55122" wide //weight: 1
        $x_1_4 = "za_number" wide //weight: 1
        $x_1_5 = "77.221.149.219" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blinerarch_AZ_2147681052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blinerarch.AZ"
        threat_id = "2147681052"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blinerarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\archive.xml" wide //weight: 1
        $x_1_2 = "http://77.221.149.219/" wide //weight: 1
        $x_1_3 = "D:\\Install\\Umenator\\PPS\\" ascii //weight: 1
        $x_1_4 = {5c 5f 5a 69 70 41 72 63 68 69 76 65 [0-3] 5c 72 65 73 5c 74 65 6d 70 5c 70 61 63 6b 65 64 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_Blinerarch_AY_2147681053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blinerarch.AY"
        threat_id = "2147681053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blinerarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autorun_homepage.exe" wide //weight: 1
        $x_1_2 = "abonent_rules" wide //weight: 1
        $x_1_3 = "SELECT * FROM AntiVirusProduct" wide //weight: 1
        $x_1_4 = "beeline" wide //weight: 1
        $x_1_5 = "phone').mask(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MSIL_Blinerarch_AV_2147681054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blinerarch.AV"
        threat_id = "2147681054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blinerarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cCountries_SelectedIndexChanged" ascii //weight: 1
        $x_1_2 = "sms_pattern" ascii //weight: 1
        $x_1_3 = "ukr_mask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blinerarch_AW_2147681055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blinerarch.AW"
        threat_id = "2147681055"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blinerarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CDATA[flashsetup]]></description><id>" ascii //weight: 1
        $x_1_2 = "ZipFlash.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blinerarch_BB_2147681056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blinerarch.BB"
        threat_id = "2147681056"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blinerarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 00 4e 00 62 00 50 00 49 00 36 00 33 00 6b 00 66 00 4b 00 51 00 37 00 75 00 72 00 46 00 4a 00 57 00 42 00 30 00 3d 00 00 31 67 00 4e 00 62 00 50 00 49 00 36 00 33 00 6b 00 66 00 4b 00 51 00 37 00 75 00 72 00 46 00 4f 00 65 00 58 00 4c 00 6c 00 62 00 4d 00 72 00 42 00}  //weight: 1, accuracy: High
        $x_1_2 = {67 00 4e 00 62 00 50 00 49 00 36 00 33 00 6b 00 66 00 4b 00 51 00 37 00 75 00 72 00 45 00 3d 00 00 09 69 00 75 00 4d 00 73 00 00 19 6b 00 63 00 61 00 56 00 50 00 4c 00 74 00 6c 00 44 00 41 00 3d 00 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {1d d0 16 d3 16 c1 16 c4 16 d0 16 cf 16 c4 16 cd 16 d3 16 d9 16 c6 16 d5 16 dd 16 dd 16 01 25 d0 16 d3 16 c1 16 c4 16 d0 16 cf 16 c4 16 cd 16 d3 16 d9 16 c6 16 ca 16 ce 16 cf 16 d7 16 d5 16 db 16 d3 16}  //weight: 1, accuracy: High
        $x_1_4 = {17 d0 16 d3 16 c1 16 c4 16 d0 16 cf 16 c4 16 cd 16 d3 16 d9 16 c6 16 01 07 ca 16 d2 16 d2 16 01 0f bf 16 c3 16 c4 16 cc 16 ca 16 d0 16 c8 16}  //weight: 1, accuracy: High
        $x_1_5 = "38Eu00zhEGvqm1YtMO14yy2N" wide //weight: 1
        $x_1_6 = "jl8vnDcuk0hdmMpQGKPGVcZRNO0=" wide //weight: 1
        $x_1_7 = "2tP5GNfMyFrB52UMnHpIJZgt" wide //weight: 1
        $x_1_8 = "sSVpa4bE3y/jbg+ezDbDbzVC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Blinerarch_BC_2147681057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blinerarch.BC"
        threat_id = "2147681057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blinerarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "6d788052:81/program/stats?homepage=1" wide //weight: 2
        $x_2_2 = {9c 16 cb 16 9f 16 a1 16 a2 16 9b 16 a1 16 9f 16 a8 16 a7 16 a1 16 a0 16}  //weight: 2, accuracy: High
        $x_2_3 = "h+E4Y6I2s3aQnw5urjZr42" wide //weight: 2
        $x_1_4 = "http://stat.openpart.ru/newtoolbar?p=ziparchive" wide //weight: 1
        $x_2_5 = {a0 16 d6 16 e2 16 eb 16 e3 16 e2 16 e6 16 d9 16 dd 16 a9 16 e8 16 f1 16 e9 16 f2 16 e8 16 e2 16 e2 16 f4 16 b1 16 e9 16 fd 16 eb 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Blinerarch_AX_2147681058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blinerarch.AX"
        threat_id = "2147681058"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blinerarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@asdasd.ru" wide //weight: 1
        $x_1_2 = {76 69 70 70 72 69 63 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "smscount" ascii //weight: 1
        $x_1_4 = {76 69 70 5f 70 61 74 74 65 72 6e 00 14 00 70 61 74 74 65 72 6e 00 75 72 6c 5f}  //weight: 1, accuracy: Low
        $x_2_5 = {0d 63 00 50 00 68 00 6f 00 6e 00 65 00 00 55 00 63 00 41 00 63 00 74 00 69 00 76 00 61 00 74 00 65 00 e0 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 2, accuracy: Low
        $x_2_6 = {63 00 69 00 5f 00 73 00 65 00 73 00 73 00 69 00 6f 00 6e 00 3d 00 28 00 5b 00 5e 00 3b 00 5d 00 2b 00 29 00 60 00 73 00 65 00 6e 00 64 00 5f 00 73 00 [0-31] 65 00 6d 00 61 00 69 00 6c 00 00 [0-31] 70 00 68 00 6f 00 6e 00 65 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Blinerarch_BA_2147681059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blinerarch.BA"
        threat_id = "2147681059"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blinerarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 6e 64 53 4d 53 00}  //weight: 1, accuracy: High
        $x_1_2 = "http://77.221.149.219" wide //weight: 1
        $x_1_3 = "subdomains_beeline" wide //weight: 1
        $x_1_4 = "html\\page.html" wide //weight: 1
        $x_1_5 = "\\html.zip" wide //weight: 1
        $x_1_6 = "<option>fuck ie!</option>" wide //weight: 1
        $x_1_7 = "html1@asdasd.ru" wide //weight: 1
        $x_1_8 = "('#za_phone').mask" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_MSIL_Blinerarch_AU_2147681060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blinerarch.AU"
        threat_id = "2147681060"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blinerarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 53 65 6e 64 53 4d 53 00}  //weight: 5, accuracy: High
        $x_5_2 = {53 4d 53 4e 6f 00 43 6f 64 65 00 43 6f 75 6e 74 72 79 49 44 00 41 72 63 68 69 76 65 49 44 00 50 61 72 74 6e 65 72 49 44}  //weight: 5, accuracy: High
        $x_1_3 = "\\program\\ziparchive_dropbox\\crypter\\obj\\Release\\crypter.pdb" ascii //weight: 1
        $x_1_4 = "http://0x6D788052:81" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

