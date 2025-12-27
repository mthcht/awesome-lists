rule Ransom_Win32_Kraken_E_2147959591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kraken.E!ldr"
        threat_id = "2147959591"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kraken"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bad path" ascii //weight: 1
        $x_1_2 = "Bad params..." ascii //weight: 1
        $x_1_3 = "My path: " ascii //weight: 1
        $x_1_4 = "Lets'go..." ascii //weight: 1
        $x_1_5 = "bad new file" ascii //weight: 1
        $x_1_6 = "bad open '%s'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Kraken_F_2147959592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kraken.F"
        threat_id = "2147959592"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kraken"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_readme_you_ws_hacked_.txt" ascii //weight: 1
        $x_1_2 = "do not crypt/delete/cleanup anything, just drop note each found folder." ascii //weight: 1
        $x_1_3 = "turn off platform specify extensions list and encrypt any found files on the disk" ascii //weight: 1
        $x_1_4 = "Threads count: bin.exe -threads 1" ascii //weight: 1
        $x_1_5 = "do not process drives; bin.exe -nodrives" ascii //weight: 1
        $x_1_6 = "do not process hyperv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

