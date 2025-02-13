rule TrojanDropper_MSIL_VB_C_2147634280_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/VB.C"
        threat_id = "2147634280"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\BFile1.exe" wide //weight: 1
        $x_1_2 = "\\BFile2.jpg" wide //weight: 1
        $x_1_3 = "D:\\Users\\Peter\\Desktop\\Stub\\Stub\\obj\\Release\\Stub.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_VB_G_2147638321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/VB.G"
        threat_id = "2147638321"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crypt_sub.Resources.resources" ascii //weight: 1
        $x_1_2 = "Coyney's Crypter\\crypt sub\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_VB_I_2147640275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/VB.I"
        threat_id = "2147640275"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "PolyXorbyMiharbiDono" ascii //weight: 4
        $x_3_2 = "PolyDeCrypt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_VB_K_2147640859_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/VB.K"
        threat_id = "2147640859"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CrypterStub" ascii //weight: 10
        $x_2_2 = "AntiZoneAlarm" ascii //weight: 2
        $x_1_3 = "IsVmWare" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_VB_N_2147643621_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/VB.N"
        threat_id = "2147643621"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "_1scantime_crypter_stub.My" ascii //weight: 4
        $x_4_2 = "_1scantime_crypter_stub.Resources.resources" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_VB_W_2147651057_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/VB.W"
        threat_id = "2147651057"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "xcfjoye.exe" ascii //weight: 2
        $x_1_2 = "RunpeClass" ascii //weight: 1
        $x_3_3 = "Release\\xcfjoye.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_VB_Y_2147651772_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/VB.Y"
        threat_id = "2147651772"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "OONSDKRhIIXNQIgKomUJ" ascii //weight: 3
        $x_2_2 = "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\vbc.exe" wide //weight: 2
        $x_3_3 = "UmVhZFByb2Nlc3NNZW1vcnk=" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_VB_AA_2147657595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/VB.AA"
        threat_id = "2147657595"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ERR 2003: " wide //weight: 2
        $x_3_2 = "TWV0aG9kSUQ=" ascii //weight: 3
        $x_3_3 = "TmFtZQ==<U21hcnRBc3NlbWJseS5BdHRyaWJ1dGVzLlBvd2VyZWRCeUF0dHJpYnV0ZQ==" ascii //weight: 3
        $x_3_4 = "X2lubmVyRXhjZXB0aW9u$VW5oYW5kbGVkRXhjZXB0aW9uLk1ldGhvZElE$VW5oYW5kbGVkRXhjZXB0aW9uLklMT2Zmc2V00VW5oYW5kbGVkRXhjZXB0aW9uLlByZXZ" ascii //weight: 3
        $x_1_5 = {52 43 34 53 54 55 42 2e 4d 79 00 73 65 6e 64 65 72 00}  //weight: 1, accuracy: High
        $n_20_6 = "Amazing Importer.exe" ascii //weight: -20
        $n_20_7 = "RedGate.SQLSearch.Addin." ascii //weight: -20
        $n_20_8 = "GAT.ACE.Properties" ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_VB_AB_2147658402_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/VB.AB"
        threat_id = "2147658402"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "New Infection!" wide //weight: 5
        $x_2_2 = "VVNFUlxTb2Z0d2FyZVxQb2xpY2llc1xNaWNyb3NvZnRcV2luZG93c1xTeXN0ZW0gL3YgRGlzYWJsZUNNRCAvdCBSRUdfRFdPUkQgL2QgMSAvZg==" wide //weight: 2
        $x_2_3 = "automation.whatismyip.com" wide //weight: 2
        $x_2_4 = "\\picture.scr" wide //weight: 2
        $x_1_5 = "sc stop wscsvc" wide //weight: 1
        $x_1_6 = "sc stop SharedAccess" wide //weight: 1
        $x_1_7 = "DisableTaskMgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_MSIL_VB_AE_2147661324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/VB.AE"
        threat_id = "2147661324"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "MartinSteel1.My" ascii //weight: 4
        $x_5_2 = "prewrite.Changlings.dll" ascii //weight: 5
        $x_7_3 = "Changlings.Mlifed, Changlings" wide //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

