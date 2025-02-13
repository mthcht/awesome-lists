rule Ransom_Win64_Sorena_2147750930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Sorena!MSR"
        threat_id = "2147750930"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Sorena"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "n -Inf.bat.cmd.com.exe3125" ascii //weight: 1
        $x_1_2 = "Encrypt.exebad" ascii //weight: 1
        $x_1_3 = "main.deriveKey" ascii //weight: 1
        $x_1_4 = "sorena Virus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

