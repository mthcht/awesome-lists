rule Ransom_Win64_QilinCrypt_PC_2147913588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/QilinCrypt.PC!MTB"
        threat_id = "2147913588"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "QilinCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Extension: " ascii //weight: 1
        $x_1_2 = "RECOVER-README.txt" ascii //weight: 1
        $x_1_3 = "Your network/system was encrypted." ascii //weight: 1
        $x_1_4 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

