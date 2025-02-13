rule Ransom_Win32_Rensen_A_2147720854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rensen.A!rsm"
        threat_id = "2147720854"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rensen"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "400"
        strings_accuracy = "High"
    strings:
        $x_100_1 = ".RENSENWARE" wide //weight: 100
        $x_100_2 = "NOT LUNATIC LEVEL" wide //weight: 100
        $x_100_3 = "ReadProcessMemory" ascii //weight: 100
        $x_100_4 = "TH12 Process Status" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

