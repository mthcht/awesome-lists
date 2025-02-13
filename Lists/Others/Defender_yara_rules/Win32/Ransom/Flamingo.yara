rule Ransom_Win32_Flamingo_SBR_2147772338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Flamingo.SBR!MSR"
        threat_id = "2147772338"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Flamingo"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "King Of Ransom" ascii //weight: 1
        $x_1_2 = "ENCRYPTER@server" ascii //weight: 1
        $x_1_3 = "ReadThis.HTA" ascii //weight: 1
        $x_1_4 = "InfoRans.txt" ascii //weight: 1
        $x_1_5 = "https://api.telegram.org/bot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

