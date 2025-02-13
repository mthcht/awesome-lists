rule Adware_Win64_OffersWizardInstaller_206930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:Win64/OffersWizardInstaller"
        threat_id = "206930"
        type = "Adware"
        platform = "Win64: Windows 64-bit platform"
        family = "OffersWizardInstaller"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 69 73 70 6c 61 79 4e 61 6d 65 00 4f 66 66 65 72 73 57 69 7a 61 72 64 20 4e 65 74 77 6f 72 6b 20 53 79 73 74 65 6d 20 44 72 69 76 65 72}  //weight: 1, accuracy: High
        $x_1_2 = "nethtsrv.exe\" -nfdi /rvm" ascii //weight: 1
        $x_1_3 = {02 25 25 5c 64 72 69 76 65 72 73 00 6e 65 74 68 66 64 72 76 2e 73 79 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

